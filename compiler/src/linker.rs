use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use amber_manifest::{CapabilityDecl, LocalComponentRef, ManifestDigest};
use amber_scenario::{
    BindingEdge, Component, ComponentId, ProvideRef, Scenario, SlotRef, graph::component_path_for,
};
use jsonschema::Validator;
use serde_json::{Map, Value};

use super::frontend::{ResolvedNode, ResolvedTree};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
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

pub fn link(tree: ResolvedTree) -> Result<Scenario, Error> {
    let mut components = Vec::new();
    let root = flatten(&tree.root, None, &mut components);

    let mut schema_cache: HashMap<ManifestDigest, Arc<Validator>> = HashMap::new();

    // Validate configs and intra-realm provide delegation before binding resolution.
    for id in (0..components.len()).map(ComponentId) {
        validate_config(id, &components, &mut schema_cache)?;
        validate_provide_delegation(id, &components)?;
    }

    let bindings = resolve_bindings(&components)?;
    validate_unique_slot_bindings(&components, &bindings)?;
    validate_all_slots_bound(&components, &bindings)?;

    Ok(Scenario {
        root,
        components,
        bindings,
    })
}

fn flatten(
    node: &ResolvedNode,
    parent: Option<ComponentId>,
    out: &mut Vec<Component>,
) -> ComponentId {
    let id = ComponentId(out.len());

    // Allocate first (children filled after recursion).
    out.push(Component {
        id,
        parent,
        name: node.name.clone(),
        declared_ref: node.declared_ref.clone(),
        resolved_url: node.resolved_url.clone(),
        digest: node.digest,
        manifest: Arc::clone(&node.manifest),
        config: node.config.clone(),
        children: BTreeMap::new(),
    });

    let mut children = BTreeMap::new();
    for (child_name, child_node) in node.children.iter() {
        let child_id = flatten(child_node, Some(id), out);
        children.insert(child_name.clone(), child_id);
    }

    out[id.0].children = children;
    id
}

fn validate_config(
    id: ComponentId,
    components: &[Component],
    schema_cache: &mut HashMap<ManifestDigest, Arc<Validator>>,
) -> Result<(), Error> {
    let c = &components[id.0];
    let Some(schema_decl) = c.manifest.config_schema.as_ref() else {
        return Ok(());
    };

    let validator = if let Some(v) = schema_cache.get(&c.digest) {
        v.clone()
    } else {
        let v = Arc::new(jsonschema::validator_for(&schema_decl.0).map_err(|e| {
            Error::InvalidConfig {
                component_path: component_path_for(components, id),
                message: e.to_string(),
            }
        })?);
        schema_cache.insert(c.digest, v.clone());
        v
    };

    // Treat missing config as `{}` for validation. (Config is expected to be an object.)
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

fn validate_provide_delegation(realm: ComponentId, components: &[Component]) -> Result<(), Error> {
    let c = &components[realm.0];
    let realm_path = component_path_for(components, realm);

    for (provide_name, provide_decl) in c.manifest.provides.iter() {
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

                // If delegating from a child, child must export that capability.
                if from_id != realm {
                    require_exported(
                        components,
                        from_id,
                        cap,
                        &realm_path,
                        provide_name,
                        "delegation source",
                    )?;
                }

                let from_manifest = &components[from_id.0].manifest;
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

fn resolve_bindings(components: &[Component]) -> Result<Vec<BindingEdge>, Error> {
    let mut edges = Vec::new();

    for realm in (0..components.len()).map(ComponentId) {
        let realm_path = component_path_for(components, realm);
        let manifest = Arc::clone(&components[realm.0].manifest);

        for b in manifest.bindings.iter() {
            let to_id = resolve_binding_component(components, realm, &b.to);
            let from_id = resolve_binding_component(components, realm, &b.from);

            // Target slot must exist.
            let to_manifest = &components[to_id.0].manifest;
            let slot_decl = if to_id == realm {
                &to_manifest.slots[&b.slot]
            } else {
                let Some(slot_decl) = to_manifest.slots.get(&b.slot) else {
                    return Err(Error::UnknownSlot {
                        component_path: component_path_for(components, to_id),
                        slot: b.slot.clone(),
                    });
                };
                // If binding reaches into a child, target name must be exported by that child.
                require_exported_simple(components, to_id, &b.slot, &realm_path)?;
                slot_decl
            };

            // Source provide must exist.
            let from_manifest = &components[from_id.0].manifest;
            let provide_decl = if from_id == realm {
                &from_manifest.provides[&b.capability]
            } else {
                let Some(provide_decl) = from_manifest.provides.get(&b.capability) else {
                    return Err(Error::UnknownProvide {
                        component_path: component_path_for(components, from_id),
                        provide: b.capability.clone(),
                    });
                };
                // If binding reaches into a child, source name must be exported by that child.
                require_exported_simple(components, from_id, &b.capability, &realm_path)?;
                provide_decl
            };

            // Type compatibility.
            let expected = &slot_decl.decl;
            let got = &provide_decl.decl;
            if expected != got {
                return Err(Error::TypeMismatch {
                    to_component_path: component_path_for(components, to_id),
                    slot: b.slot.clone(),
                    expected: expected.clone(),
                    got: got.clone(),
                });
            }

            // Normalize delegated provides so Scenario edges point at the origin.
            let origin = canonicalize_provide(components, from_id, &b.capability)?;

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
) -> ComponentId {
    match reference {
        LocalComponentRef::Self_ => realm,
        LocalComponentRef::Child(name) => components[realm.0].children[name],
        _ => unreachable!("unsupported local component reference"),
    }
}

fn resolve_local_component<'a>(
    components: &[Component],
    realm: ComponentId,
    reference: &'a LocalComponentRef,
) -> Result<ComponentId, &'a str> {
    match reference {
        LocalComponentRef::Self_ => Ok(realm),
        LocalComponentRef::Child(name) => components[realm.0]
            .children
            .get(name)
            .copied()
            .ok_or(name.as_str()),
        _ => unreachable!("unsupported local component reference"),
    }
}

/// Resolve a provide through delegation to its origin.
fn canonicalize_provide(
    components: &[Component],
    start_component: ComponentId,
    start_name: &str,
) -> Result<ProvideRef, Error> {
    let mut cur_component = start_component;
    let mut cur_name: &str = start_name;
    let mut remaining_in_component = components[cur_component.0].manifest.provides.len() + 1;

    loop {
        if remaining_in_component == 0 {
            return Err(Error::InvalidProvideDelegation {
                component_path: component_path_for(components, cur_component),
                provide: cur_name.to_string(),
                message: "cycle detected while resolving provide delegation".to_string(),
            });
        }

        let manifest = &components[cur_component.0].manifest;
        let provide_decl = &manifest.provides[cur_name];

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
                    remaining_in_component =
                        components[cur_component.0].manifest.provides.len() + 1;
                }

                cur_name = cap;
            }
            _ => unreachable!("provide delegation validated earlier"),
        }
    }
}

fn validate_all_slots_bound(
    components: &[Component],
    bindings: &[BindingEdge],
) -> Result<(), Error> {
    // Build a quick lookup of satisfied slots.
    let mut satisfied: HashMap<(ComponentId, &str), ()> = HashMap::new();
    for b in bindings {
        satisfied.insert((b.to.component, b.to.name.as_str()), ());
    }

    for id in (0..components.len()).map(ComponentId) {
        let c = &components[id.0];
        for slot_name in c.manifest.slots.keys() {
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

fn require_exported_simple(
    components: &[Component],
    target: ComponentId,
    name: &str,
    _realm_path: &str,
) -> Result<(), Error> {
    let target_path = component_path_for(components, target);
    if !components[target.0].manifest.exports.contains(name) {
        return Err(Error::NotExported {
            component_path: target_path,
            name: name.to_string(),
        });
    }
    Ok(())
}

// More context-rich version for provide delegation errors.
fn require_exported(
    components: &[Component],
    target: ComponentId,
    name: &str,
    realm_path: &str,
    provide: &str,
    _context: &str,
) -> Result<(), Error> {
    if components[target.0].manifest.exports.contains(name) {
        return Ok(());
    }
    Err(Error::InvalidProvideDelegation {
        component_path: realm_path.to_string(),
        provide: provide.to_string(),
        message: format!(
            "delegation references non-exported `{}` on {}",
            name,
            component_path_for(components, target)
        ),
    })
}
