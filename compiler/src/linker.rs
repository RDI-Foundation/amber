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

            edges.push(BindingEdge {
                from: ProvideRef {
                    component: from_id,
                    name: b.capability.clone(),
                },
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
