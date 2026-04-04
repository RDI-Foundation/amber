use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use amber_config as rc;
use amber_manifest::{CapabilityDecl, NetworkProtocol};
use amber_scenario::Scenario;
use serde_json::Value;

use crate::targets::{
    mesh::plan::{MeshPlan, component_label},
    program_config::ConfigPlan,
};

#[derive(Clone, Debug)]
pub(crate) struct RuntimeInterface {
    pub(crate) root_inputs: BTreeMap<String, RootInputDescriptor>,
    pub(crate) external_slots: BTreeMap<String, ExternalSlotDescriptor>,
    pub(crate) exports: BTreeMap<String, ExportDescriptor>,
}

#[derive(Clone, Debug)]
pub(crate) struct RootInputDescriptor {
    pub(crate) env_var: String,
    pub(crate) required: bool,
    pub(crate) secret: bool,
    pub(crate) default_value: Option<Value>,
    pub(crate) runtime_used: bool,
}

impl RootInputDescriptor {
    pub(crate) fn default_env_value(
        &self,
        path: &str,
    ) -> Result<Option<String>, RuntimeInterfaceError> {
        self.default_value
            .as_ref()
            .map(rc::encode_env_value)
            .transpose()
            .map_err(|err| {
                RuntimeInterfaceError::new(format!(
                    "failed to render default for config.{path}: {err}"
                ))
            })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ExternalSlotDescriptor {
    pub(crate) decl: CapabilityDecl,
    pub(crate) required: bool,
    pub(crate) url_env: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ExportDescriptor {
    pub(crate) component: String,
    pub(crate) provide: String,
    pub(crate) protocol: NetworkProtocol,
}

#[derive(Debug)]
pub(crate) struct RuntimeInterfaceError {
    message: String,
}

impl RuntimeInterfaceError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for RuntimeInterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RuntimeInterfaceError {}

pub(crate) fn build_runtime_interface(
    scenario: &Scenario,
    mesh_plan: &MeshPlan,
    config_plan: &ConfigPlan,
) -> Result<RuntimeInterface, RuntimeInterfaceError> {
    Ok(RuntimeInterface {
        root_inputs: collect_root_inputs(config_plan)?,
        external_slots: collect_external_slots(
            scenario,
            mesh_plan
                .external_bindings()
                .map(|binding| binding.external_slot.as_str()),
        ),
        exports: collect_exports(scenario, mesh_plan),
    })
}

pub(crate) fn collect_root_inputs(
    config_plan: &ConfigPlan,
) -> Result<BTreeMap<String, RootInputDescriptor>, RuntimeInterfaceError> {
    let runtime_root_paths = collect_runtime_root_paths(config_plan);
    let mut out = BTreeMap::new();

    for leaf in &config_plan.root_leaves {
        let env_var = rc::env_var_for_path(&leaf.path).map_err(|err| {
            RuntimeInterfaceError::new(format!("failed to map config path {}: {err}", leaf.path))
        })?;
        out.insert(
            leaf.path.clone(),
            RootInputDescriptor {
                env_var,
                required: leaf.runtime_required(),
                secret: leaf.secret,
                default_value: leaf.default.clone(),
                runtime_used: runtime_root_paths.contains(&leaf.path),
            },
        );
    }

    Ok(out)
}

pub(crate) fn collect_external_slots<'a>(
    scenario: &Scenario,
    external_slot_names: impl IntoIterator<Item = &'a str>,
) -> BTreeMap<String, ExternalSlotDescriptor> {
    let root_component = scenario.component(scenario.root);
    let mut slot_names = BTreeSet::new();
    for name in external_slot_names {
        slot_names.insert(name.to_string());
    }

    let mut out = BTreeMap::new();
    for name in slot_names {
        let decl = root_component
            .slots
            .get(name.as_str())
            .expect("external slot should exist on root");
        out.insert(
            name.clone(),
            ExternalSlotDescriptor {
                decl: decl.decl.clone(),
                required: !decl.optional,
                url_env: external_slot_env_var(&name),
            },
        );
    }

    out
}

pub(crate) fn collect_exports(
    scenario: &Scenario,
    mesh_plan: &MeshPlan,
) -> BTreeMap<String, ExportDescriptor> {
    let mut out = BTreeMap::new();
    for export in mesh_plan.exports() {
        out.insert(
            export.name.clone(),
            ExportDescriptor {
                component: component_label(scenario, export.provider),
                provide: export.provide.clone(),
                protocol: export.endpoint.protocol,
            },
        );
    }
    out
}

pub fn external_slot_env_var(slot: &str) -> String {
    let mut out = String::from("AMBER_EXTERNAL_SLOT_");
    for ch in slot.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out.push_str("_URL");
    out
}

fn collect_runtime_root_paths(config_plan: &ConfigPlan) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for view in config_plan.runtime_views.values() {
        out.extend(view.allowed_root_leaf_paths.iter().cloned());
    }
    for plan in config_plan.program_plans.values() {
        if let Some(image) = plan.image() {
            image.collect_runtime_root_paths(&mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use amber_manifest::{CapabilityKind, ManifestDigest};
    use amber_scenario::{Component, ComponentId, Moniker};
    use serde_json::json;

    use super::*;
    use crate::{
        config::scope::RuntimeConfigView,
        targets::program_config::{
            ProgramImageOrigin, ProgramImagePart, ProgramImagePlan, ProgramPlan, ProgramSourcePlan,
        },
    };

    fn digest(byte: u8) -> ManifestDigest {
        ManifestDigest::new([byte; 32])
    }

    fn moniker(path: &str) -> Moniker {
        Moniker::from(Arc::from(path))
    }

    fn component(id: usize, path: &str) -> Component {
        Component {
            id: ComponentId(id),
            parent: None,
            moniker: moniker(path),
            digest: digest(id as u8),
            config: None,
            config_schema: None,
            program: None,
            slots: BTreeMap::new(),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            metadata: None,
            child_templates: BTreeMap::new(),
            children: Vec::new(),
        }
    }

    #[test]
    fn collect_root_inputs_marks_runtime_used_paths() {
        let config_plan = ConfigPlan {
            root_leaves: vec![
                rc::SchemaLeaf {
                    path: "api.url".to_string(),
                    required: true,
                    default: None,
                    secret: false,
                    pointer: "/properties/api/properties/url".to_string(),
                },
                rc::SchemaLeaf {
                    path: "api.token".to_string(),
                    required: false,
                    default: Some(json!("secret")),
                    secret: true,
                    pointer: "/properties/api/properties/token".to_string(),
                },
            ],
            program_plans: HashMap::from([(
                ComponentId(1),
                ProgramPlan::Resolved {
                    source: ProgramSourcePlan::Image {
                        image: ProgramImagePlan::RuntimeTemplate(vec![
                            ProgramImagePart::Literal("ghcr.io/example/".to_string()),
                            ProgramImagePart::RootConfigPath("api.url".to_string()),
                        ]),
                        image_origin: ProgramImageOrigin::ProgramImage,
                    },
                    entrypoint: Vec::new(),
                    env: BTreeMap::new(),
                },
            )]),
            mount_specs: Default::default(),
            needs_helper: false,
            needs_runtime_config: true,
            runtime_views: HashMap::from([(
                ComponentId(1),
                RuntimeConfigView {
                    allowed_root_leaf_paths: BTreeSet::from(["api.token".to_string()]),
                    pruned_root_schema: json!({}),
                    component_template: rc::RootConfigTemplate::Root,
                    component_schema: json!({}),
                },
            )]),
        };

        let root_inputs = collect_root_inputs(&config_plan).expect("root inputs should collect");
        assert!(root_inputs["api.url"].runtime_used);
        assert!(root_inputs["api.token"].runtime_used);
        assert_eq!(root_inputs["api.url"].env_var, "AMBER_CONFIG_API__URL");
        assert_eq!(
            root_inputs["api.token"]
                .default_env_value("api.token")
                .expect("default should encode"),
            Some("\"secret\"".to_string())
        );
    }

    #[test]
    fn collect_external_slots_deduplicates_names() {
        let mut root = component(0, "/");
        root.slots.insert(
            "api".to_string(),
            serde_json::from_value(json!({
                "kind": "http",
            }))
            .expect("slot decl"),
        );
        let scenario = Scenario {
            root: ComponentId(0),
            components: vec![Some(root)],
            bindings: Vec::new(),
            exports: Vec::new(),
            manifest_catalog: BTreeMap::new(),
        };

        let slots = collect_external_slots(&scenario, ["api", "api"]);
        assert_eq!(slots.len(), 1);
        assert_eq!(slots["api"].decl.kind, CapabilityKind::Http);
        assert_eq!(slots["api"].url_env, "AMBER_EXTERNAL_SLOT_API_URL");
        assert!(slots["api"].required);
    }

    #[test]
    fn collect_exports_uses_component_labels() {
        let root = component(0, "/");
        let mut child = component(1, "/server");
        child.parent = Some(ComponentId(0));
        child.provides.insert(
            "api".to_string(),
            serde_json::from_value(json!({
                "kind": "http",
                "endpoint": "api",
            }))
            .expect("provide decl"),
        );

        let scenario = Scenario {
            root: ComponentId(0),
            components: vec![Some(root), Some(child)],
            bindings: Vec::new(),
            exports: Vec::new(),
            manifest_catalog: BTreeMap::new(),
        };
        let mesh_plan = MeshPlan::new(
            vec![ComponentId(1)],
            Vec::new(),
            vec![crate::targets::mesh::plan::ResolvedExport {
                name: "public".to_string(),
                provider: ComponentId(1),
                provide: "api".to_string(),
                endpoint: crate::targets::mesh::plan::EndpointInfo {
                    port: 8080,
                    protocol: NetworkProtocol::Http,
                },
            }],
            Default::default(),
        );

        let exports = collect_exports(&scenario, &mesh_plan);
        assert_eq!(exports["public"].component, "/server");
        assert_eq!(exports["public"].provide, "api");
        assert_eq!(exports["public"].protocol, NetworkProtocol::Http);
    }
}
