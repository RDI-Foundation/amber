use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use amber_manifest::{
    BindingSource, BindingTarget, CapabilityDecl, ChildName, ExportName, ExportTarget, Manifest,
    ManifestDigest,
};
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

    #[error("invalid export `{name}` on {component_path}: {message}")]
    InvalidExport {
        component_path: String,
        name: String,
        message: String,
    },

    #[error("`{name}` on {component_path} is exported as a {actual} (expected {expected})")]
    ExportKindMismatch {
        component_path: String,
        name: String,
        expected: &'static str,
        actual: &'static str,
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

    #[error("invalid config for {component_path}: {message}")]
    InvalidConfig {
        component_path: String,
        message: String,
    },

    #[error("unsupported manifest feature `{feature}` in {component_path}")]
    UnsupportedManifestFeature {
        component_path: String,
        feature: &'static str,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExportKind {
    Slot,
    Provide,
}

impl ExportKind {
    fn as_str(self) -> &'static str {
        match self {
            ExportKind::Slot => "slot",
            ExportKind::Provide => "provide",
        }
    }
}

pub(crate) struct ResolvedExport {
    pub(crate) component: ComponentId,
    pub(crate) name: String,
    pub(crate) decl: CapabilityDecl,
    pub(crate) kind: ExportKind,
}

pub fn link(tree: ResolvedTree, store: &DigestStore) -> Result<(Scenario, Provenance), Error> {
    let mut components = Vec::new();
    let mut provenance = Provenance::default();
    let root = flatten(&tree.root, None, &mut components, &mut provenance);

    debug_assert_eq!(components.len(), provenance.components.len());

    let manifests = build_manifest_table(&components, store)?;

    for (c, m) in components.iter_mut().zip(&manifests) {
        c.has_program = m.program().is_some();
    }

    let mut schema_cache: HashMap<ManifestDigest, Arc<Validator>> = HashMap::new();

    for id in (0..components.len()).map(ComponentId) {
        validate_config(id, &components, &manifests, &mut schema_cache)?;
        validate_exports(id, &components, &manifests)?;
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
        has_program: false,
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

    let Some(schema_decl) = m.config_schema() else {
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

fn validate_exports(
    realm: ComponentId,
    components: &[Component],
    manifests: &[Arc<Manifest>],
) -> Result<(), Error> {
    let realm_manifest = &manifests[realm.0];
    let realm_path = component_path_for(components, realm);

    for (export_name, target) in realm_manifest.exports().iter() {
        let ExportTarget::ChildExport { child, export } = target else {
            continue;
        };

        let child_id = child_component_id(components, realm, child)?;
        if let Err(err) = resolve_export(components, manifests, child_id, export) {
            let message = match err {
                Error::NotExported {
                    component_path,
                    name,
                } => format!("target references non-exported `{name}` on {component_path}"),
                other => return Err(other),
            };
            return Err(Error::InvalidExport {
                component_path: realm_path.clone(),
                name: export_name.to_string(),
                message,
            });
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

        for (target, binding) in realm_manifest.bindings().iter() {
            let (slot_ref, slot_decl, to_id, slot_name_for_err) =
                match target {
                    BindingTarget::SelfSlot(slot_name) => {
                        let to_id = realm;
                        let to_manifest = &manifests[to_id.0];
                        let slot_decl = to_manifest.slots().get(slot_name).ok_or_else(|| {
                            Error::UnknownSlot {
                                component_path: component_path_for(components, to_id),
                                slot: slot_name.to_string(),
                            }
                        })?;
                        let slot_name = slot_name.to_string();
                        (
                            SlotRef {
                                component: to_id,
                                name: slot_name.clone(),
                            },
                            slot_decl.decl.clone(),
                            to_id,
                            slot_name,
                        )
                    }
                    BindingTarget::ChildExport { child, export } => {
                        let to_id = child_component_id(components, realm, child)?;
                        let ResolvedExport {
                            component,
                            name,
                            decl,
                            kind,
                        } = resolve_export(components, manifests, to_id, export)?;
                        if kind != ExportKind::Slot {
                            return Err(Error::ExportKindMismatch {
                                component_path: component_path_for(components, to_id),
                                name: export.to_string(),
                                expected: ExportKind::Slot.as_str(),
                                actual: kind.as_str(),
                            });
                        }
                        (SlotRef { component, name }, decl, to_id, export.to_string())
                    }
                    _ => {
                        return Err(Error::UnsupportedManifestFeature {
                            component_path: component_path_for(components, realm),
                            feature: "binding target",
                        });
                    }
                };

            let (provide_ref, provide_decl) = match &binding.from {
                BindingSource::SelfProvide(provide_name) => {
                    let from_id = realm;
                    let from_manifest = &manifests[from_id.0];
                    let provide_decl =
                        from_manifest.provides().get(provide_name).ok_or_else(|| {
                            Error::UnknownProvide {
                                component_path: component_path_for(components, from_id),
                                provide: provide_name.to_string(),
                            }
                        })?;
                    (
                        ProvideRef {
                            component: from_id,
                            name: provide_name.to_string(),
                        },
                        provide_decl.decl.clone(),
                    )
                }
                BindingSource::ChildExport { child, export } => {
                    let from_id = child_component_id(components, realm, child)?;
                    let ResolvedExport {
                        component,
                        name,
                        decl,
                        kind,
                    } = resolve_export(components, manifests, from_id, export)?;
                    if kind != ExportKind::Provide {
                        return Err(Error::ExportKindMismatch {
                            component_path: component_path_for(components, from_id),
                            name: export.to_string(),
                            expected: ExportKind::Provide.as_str(),
                            actual: kind.as_str(),
                        });
                    }
                    (ProvideRef { component, name }, decl)
                }
                _ => {
                    return Err(Error::UnsupportedManifestFeature {
                        component_path: component_path_for(components, realm),
                        feature: "binding source",
                    });
                }
            };

            if slot_decl != provide_decl {
                return Err(Error::TypeMismatch {
                    to_component_path: component_path_for(components, to_id),
                    slot: slot_name_for_err,
                    expected: slot_decl,
                    got: provide_decl,
                });
            }

            edges.push(BindingEdge {
                from: provide_ref,
                to: slot_ref,
                weak: binding.weak,
            });
        }
    }

    Ok(edges)
}

fn child_component_id(
    components: &[Component],
    realm: ComponentId,
    child: &ChildName,
) -> Result<ComponentId, Error> {
    components[realm.0]
        .children
        .get(child.as_str())
        .copied()
        .ok_or_else(|| Error::UnknownChild {
            component_path: component_path_for(components, realm),
            child: child.to_string(),
        })
}

pub(crate) fn resolve_export(
    components: &[Component],
    manifests: &[Arc<Manifest>],
    component: ComponentId,
    export_name: &ExportName,
) -> Result<ResolvedExport, Error> {
    let manifest = &manifests[component.0];
    let Some(target) = manifest.exports().get(export_name) else {
        return Err(Error::NotExported {
            component_path: component_path_for(components, component),
            name: export_name.to_string(),
        });
    };

    match target {
        ExportTarget::SelfSlot(slot_name) => {
            let slot_decl = manifest
                .slots()
                .get(slot_name)
                .ok_or_else(|| Error::UnknownSlot {
                    component_path: component_path_for(components, component),
                    slot: slot_name.to_string(),
                })?;
            Ok(ResolvedExport {
                component,
                name: slot_name.to_string(),
                decl: slot_decl.decl.clone(),
                kind: ExportKind::Slot,
            })
        }
        ExportTarget::SelfProvide(provide_name) => {
            let provide_decl =
                manifest
                    .provides()
                    .get(provide_name)
                    .ok_or_else(|| Error::UnknownProvide {
                        component_path: component_path_for(components, component),
                        provide: provide_name.to_string(),
                    })?;
            Ok(ResolvedExport {
                component,
                name: provide_name.to_string(),
                decl: provide_decl.decl.clone(),
                kind: ExportKind::Provide,
            })
        }
        ExportTarget::ChildExport { child, export } => {
            let child_id = child_component_id(components, component, child)?;
            resolve_export(components, manifests, child_id, export)
        }
        _ => Err(Error::UnsupportedManifestFeature {
            component_path: component_path_for(components, component),
            feature: "export target",
        }),
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
        for slot_name in m.slots().keys() {
            if satisfied.contains_key(&(id, slot_name.as_str())) {
                continue;
            }
            return Err(Error::UnboundSlot {
                component_path: component_path_for(components, id),
                slot: slot_name.to_string(),
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
