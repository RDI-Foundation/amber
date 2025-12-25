use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use amber_manifest::{CapabilityDecl, LocalComponentRef, Manifest, ManifestDigest};
use amber_scenario::{
    BindingEdge, Component, ComponentId, ProvideRef, Scenario, SlotRef, graph::component_path_for,
};
use jsonschema::Validator;
use serde_json::{Map, Value};

use super::frontend::{ResolvedNode, ResolvedTree};
use crate::{ComponentProvenance, DigestStore, Provenance};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("missing manifest content for {component_path} (digest {digest})")]
    MissingManifest {
        component_path: String,
        digest: ManifestDigest,
    },

    #[error("binding references unknown child `#{child}` in {component_path}")]
    UnknownChild {
        component_path: String,
        child: String,
    },

    #[error("unknown slot `{slot}` on {component_path}")]
    UnknownSlot {
        component_path: String,
        slot: String,
    },

    #[error("unknown provide `{provide}` on {component_path}")]
    UnknownProvide {
        component_path: String,
        provide: String,
    },

    #[error("`{name}` is not exported by {component_path}")]
    NotExported {
        component_path: String,
        name: String,
    },

    #[error(
        "type mismatch binding into {to_component_path}.{slot}: expected {expected:?}, got {got:?}"
    )]
    TypeMismatch {
        to_component_path: String,
        slot: String,
        expected: CapabilityDecl,
        got: CapabilityDecl,
    },

    #[error("slot `{slot}` on {component_path} is not bound (non-optional slots must be filled)")]
    UnboundSlot {
        component_path: String,
        slot: String,
    },

    #[error(
        "slot `{slot}` on {to_component_path} is bound more than once (from {first_from} and \
         {second_from})"
    )]
    DuplicateSlotBinding {
        to_component_path: String,
        slot: String,
        first_from: String,
        second_from: String,
    },

    #[error("invalid provide delegation on {component_path}.{provide}: {message}")]
    InvalidProvideDelegation {
        component_path: String,
        provide: String,
        message: String,
    },

    #[error("invalid config for {component_path}: {message}")]
    InvalidConfig {
        component_path: String,
        message: String,
    },
}

pub fn link(tree: ResolvedTree, store: &DigestStore) -> Result<(Scenario, Provenance), Error> {
    let mut components = Vec::new();
    let mut provenance = Provenance::default();
    let root = flatten(&tree.root, None, &mut components, &mut provenance);

    debug_assert_eq!(components.len(), provenance.components.len());

    let manifests = build_manifest_table(&components, store)?;

    let mut schema_cache: HashMap<ManifestDigest, Arc<Validator>> = HashMap::new();

    for id in (0..components.len()).map(ComponentId) {
        validate_config(id, &components, &manifests, &mut schema_cache)?;
        validate_provide_delegation(id, &components, &manifests)?;
    }

    let bindings = resolve_bindings(&components, &manifests)?;
    validate_unique_slot_bindings(&components, &bindings)?;
    validate_all_slots_bound(&components, &manifests, &bindings)?;

    Ok((
        Scenario {
            root,
            components,
            bindings,
        },
        provenance,
    ))
}

fn build_manifest_table(
    components: &[Component],
    store: &DigestStore,
) -> Result<Vec<Arc<Manifest>>, Error> {
    let mut out = Vec::with_capacity(components.len());
    for id in (0..components.len()).map(ComponentId) {
        let digest = components[id.0].digest;
        let Some(manifest) = store.get(&digest) else {
            return Err(Error::MissingManifest {
                component_path: component_path_for(components, id),
                digest,
            });
        };
        out.push(manifest);
    }
    Ok(out)
}

fn flatten(
    node: &ResolvedNode,
    parent: Option<ComponentId>,
    out: &mut Vec<Component>,
    prov: &mut Provenance,
) -> ComponentId {
    let id = ComponentId(out.len());

    out.push(Component {
        id,
        parent,
        name: node.name.clone(),
        digest: node.digest,
        config: node.config.clone(),
        children: BTreeMap::new(),
    });

    prov.components.push(ComponentProvenance {
        declared_ref: node.declared_ref.clone(),
        digest: node.digest,
        observed_url: node.observed_url.clone(),
    });

    let mut children = BTreeMap::new();
    for (child_name, child_node) in node.children.iter() {
        let child_id = flatten(child_node, Some(id), out, prov);
        children.insert(child_name.clone(), child_id);
    }

    out[id.0].children = children;
    id
}

fn validate_config(
    id: ComponentId,
    components: &[Component],
    manifests: &[Arc<Manifest>],
    schema_cache: &mut HashMap<ManifestDigest, Arc<Validator>>,
) -> Result<(), Error> {
    let c = &components[id.0];
    let m = &manifests[id.0];

    let Some(schema_decl) = m.config_schema.as_ref() else {
        return Ok(());
    };

    let validator = if let Some(v) = schema_cache.get(&c.digest) {
        Arc::clone(v)
    } else {
        let v = Arc::new(jsonschema::validator_for(&schema_decl.0).map_err(|e| {
            Error::InvalidConfig {
                component_path: component_path_for(components, id),
                message: e.to_string(),
            }
        })?);
        schema_cache.insert(c.digest, Arc::clone(&v));
        v
    };

    let empty = Value::Object(Map::new());
    let effective = c.config.as_ref().unwrap_or(&empty);

    let mut errors = validator.iter_errors(effective);
    let Some(first) = errors.next() else {
        return Ok(());
    };

    let mut msgs = vec![first.to_string()];
    msgs.extend(errors.take(7).map(|e| e.to_string()));
    Err(Error::InvalidConfig {
        component_path: component_path_for(components, id),
        message: msgs.join("; "),
    })
}

fn validate_provide_delegation(
    realm: ComponentId,
    components: &[Component],
    manifests: &[Arc<Manifest>],
) -> Result<(), Error> {
    let realm_manifest = &manifests[realm.0];
    let realm_path = component_path_for(components, realm);

    for (provide_name, provide_decl) in realm_manifest.provides.iter() {
        match (&provide_decl.from, &provide_decl.capability) {
            (None, None) => {}
            (Some(from), Some(cap)) => {
                let from_id = resolve_local_component(components, realm, from).map_err(|_| {
                    Error::InvalidProvideDelegation {
                        component_path: realm_path.clone(),
                        provide: provide_name.clone(),
                        message: format!("unknown `from` component ref `{from}`"),
                    }
                })?;

                if from_id != realm && !manifests[from_id.0].exports.contains(cap) {
                    return Err(Error::InvalidProvideDelegation {
                        component_path: realm_path.clone(),
                        provide: provide_name.clone(),
                        message: format!(
                            "delegation references non-exported `{}` on {}",
                            cap,
                            component_path_for(components, from_id)
                        ),
                    });
                }

                let from_manifest = &manifests[from_id.0];
                let Some(src_decl) = from_manifest.provides.get(cap) else {
                    return Err(Error::InvalidProvideDelegation {
                        component_path: realm_path.clone(),
                        provide: provide_name.clone(),
                        message: format!("`from` component does not provide `{cap}`"),
                    });
                };

                if src_decl.decl != provide_decl.decl {
                    return Err(Error::InvalidProvideDelegation {
                        component_path: realm_path.clone(),
                        provide: provide_name.clone(),
                        message: format!(
                            "type mismatch: declared {:?}, source {:?}",
                            provide_decl.decl, src_decl.decl
                        ),
                    });
                }
            }
            _ => {
                return Err(Error::InvalidProvideDelegation {
                    component_path: realm_path.clone(),
                    provide: provide_name.clone(),
                    message: "expected both `from` and `capability`, or neither".to_string(),
                });
            }
        }
    }

    Ok(())
}

fn resolve_bindings(
    components: &[Component],
    manifests: &[Arc<Manifest>],
) -> Result<Vec<BindingEdge>, Error> {
    let mut edges = Vec::new();

    for realm in (0..components.len()).map(ComponentId) {
        let realm_manifest = &manifests[realm.0];

        for b in realm_manifest.bindings.iter() {
            let to_id = resolve_binding_component(components, realm, &b.to)?;
            let from_id = resolve_binding_component(components, realm, &b.from)?;

            let to_manifest = &manifests[to_id.0];
            let slot_decl = to_manifest
                .slots
                .get(&b.slot)
                .ok_or_else(|| Error::UnknownSlot {
                    component_path: component_path_for(components, to_id),
                    slot: b.slot.clone(),
                })?;
            if to_id != realm && !to_manifest.exports.contains(&b.slot) {
                return Err(Error::NotExported {
                    component_path: component_path_for(components, to_id),
                    name: b.slot.clone(),
                });
            }

            let from_manifest = &manifests[from_id.0];
            let provide_decl =
                from_manifest
                    .provides
                    .get(&b.capability)
                    .ok_or_else(|| Error::UnknownProvide {
                        component_path: component_path_for(components, from_id),
                        provide: b.capability.clone(),
                    })?;
            if from_id != realm && !from_manifest.exports.contains(&b.capability) {
                return Err(Error::NotExported {
                    component_path: component_path_for(components, from_id),
                    name: b.capability.clone(),
                });
            }

            if slot_decl.decl != provide_decl.decl {
                return Err(Error::TypeMismatch {
                    to_component_path: component_path_for(components, to_id),
                    slot: b.slot.clone(),
                    expected: slot_decl.decl.clone(),
                    got: provide_decl.decl.clone(),
                });
            }

            let origin = canonicalize_provide(components, manifests, from_id, &b.capability)?;

            edges.push(BindingEdge {
                from: origin,
                to: SlotRef {
                    component: to_id,
                    name: b.slot.clone(),
                },
                weak: b.weak,
            });
        }
    }

    Ok(edges)
}

fn resolve_binding_component(
    components: &[Component],
    realm: ComponentId,
    reference: &LocalComponentRef,
) -> Result<ComponentId, Error> {
    match reference {
        LocalComponentRef::Self_ => Ok(realm),
        LocalComponentRef::Child(name) => components[realm.0]
            .children
            .get(name)
            .copied()
            .ok_or_else(|| Error::UnknownChild {
                component_path: component_path_for(components, realm),
                child: name.clone(),
            }),
        _ => unreachable!("unsupported local component reference"),
    }
}

fn resolve_local_component(
    components: &[Component],
    realm: ComponentId,
    reference: &LocalComponentRef,
) -> Result<ComponentId, String> {
    match reference {
        LocalComponentRef::Self_ => Ok(realm),
        LocalComponentRef::Child(name) => components[realm.0]
            .children
            .get(name)
            .copied()
            .ok_or_else(|| name.clone()),
        _ => unreachable!("unsupported local component reference"),
    }
}

fn canonicalize_provide(
    components: &[Component],
    manifests: &[Arc<Manifest>],
    start_component: ComponentId,
    start_name: &str,
) -> Result<ProvideRef, Error> {
    let mut cur_component = start_component;
    let mut cur_name: &str = start_name;
    let mut remaining_in_component = manifests[cur_component.0].provides.len() + 1;

    loop {
        if remaining_in_component == 0 {
            return Err(Error::InvalidProvideDelegation {
                component_path: component_path_for(components, cur_component),
                provide: cur_name.to_string(),
                message: "cycle detected while resolving provide delegation".to_string(),
            });
        }

        let manifest = &manifests[cur_component.0];
        let provide_decl =
            manifest
                .provides
                .get(cur_name)
                .ok_or_else(|| Error::UnknownProvide {
                    component_path: component_path_for(components, cur_component),
                    provide: cur_name.to_string(),
                })?;

        match (
            provide_decl.from.as_ref(),
            provide_decl.capability.as_deref(),
        ) {
            (None, None) => {
                return Ok(ProvideRef {
                    component: cur_component,
                    name: cur_name.to_string(),
                });
            }
            (Some(from), Some(cap)) => {
                let next_component = resolve_local_component(components, cur_component, from)
                    .unwrap_or_else(|_| unreachable!("provide delegation validated earlier"));

                if next_component == cur_component {
                    remaining_in_component -= 1;
                } else {
                    cur_component = next_component;
                    remaining_in_component = manifests[cur_component.0].provides.len() + 1;
                }

                cur_name = cap;
            }
            _ => unreachable!("provide delegation validated earlier"),
        }
    }
}

fn validate_all_slots_bound(
    components: &[Component],
    manifests: &[Arc<Manifest>],
    bindings: &[BindingEdge],
) -> Result<(), Error> {
    let mut satisfied: HashMap<(ComponentId, &str), ()> = HashMap::new();
    for b in bindings {
        satisfied.insert((b.to.component, b.to.name.as_str()), ());
    }

    for id in (0..components.len()).map(ComponentId) {
        let m = &manifests[id.0];
        for slot_name in m.slots.keys() {
            if satisfied.contains_key(&(id, slot_name.as_str())) {
                continue;
            }
            return Err(Error::UnboundSlot {
                component_path: component_path_for(components, id),
                slot: slot_name.clone(),
            });
        }
    }

    Ok(())
}

fn validate_unique_slot_bindings(
    components: &[Component],
    bindings: &[BindingEdge],
) -> Result<(), Error> {
    let mut seen: HashMap<(ComponentId, String), ProvideRef> = HashMap::new();

    for b in bindings {
        let key = (b.to.component, b.to.name.clone());
        if let Some(prev_from) = seen.insert(key, b.from.clone()) {
            let to_component_path = component_path_for(components, b.to.component);

            let first_from = format!(
                "{}.{}",
                component_path_for(components, prev_from.component),
                prev_from.name
            );
            let second_from = format!(
                "{}.{}",
                component_path_for(components, b.from.component),
                b.from.name
            );

            return Err(Error::DuplicateSlotBinding {
                to_component_path,
                slot: b.to.name.clone(),
                first_from,
                second_from,
            });
        }
    }

    Ok(())
}
