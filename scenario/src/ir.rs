use std::collections::BTreeMap;

use amber_manifest::{
    CapabilityDecl, FrameworkCapabilityName, ManifestDigest, Program, ProvideDecl, SlotDecl,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, Scenario,
    ScenarioExport, SlotRef,
};

pub const SCENARIO_IR_SCHEMA: &str = "amber.scenario.ir";
pub const SCENARIO_IR_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScenarioIr {
    pub schema: String,
    pub version: u32,
    pub root: usize,
    pub components: Vec<ComponentIr>,
    pub bindings: Vec<BindingIr>,
    pub exports: Vec<ExportIr>,
}

impl From<&Scenario> for ScenarioIr {
    fn from(scenario: &Scenario) -> Self {
        let components = scenario
            .components_iter()
            .map(|(id, component)| ComponentIr::from_component(id, component))
            .collect();
        let bindings = scenario.bindings.iter().map(BindingIr::from).collect();
        let exports = scenario.exports.iter().map(ExportIr::from).collect();

        Self {
            schema: SCENARIO_IR_SCHEMA.to_string(),
            version: SCENARIO_IR_VERSION,
            root: scenario.root.0,
            components,
            bindings,
            exports,
        }
    }
}

impl TryFrom<ScenarioIr> for Scenario {
    type Error = ScenarioIrError;

    fn try_from(ir: ScenarioIr) -> Result<Self, Self::Error> {
        if ir.schema != SCENARIO_IR_SCHEMA {
            return Err(ScenarioIrError::SchemaMismatch {
                expected: SCENARIO_IR_SCHEMA,
                actual: ir.schema,
            });
        }
        if ir.version != SCENARIO_IR_VERSION {
            return Err(ScenarioIrError::VersionMismatch {
                expected: SCENARIO_IR_VERSION,
                actual: ir.version,
            });
        }

        let max_id = ir
            .components
            .iter()
            .map(|component| component.id)
            .chain(std::iter::once(ir.root))
            .max()
            .expect("root id should be present");
        let mut components = vec![None; max_id + 1];

        for component in ir.components {
            let id = component.id;
            if components[id].is_some() {
                return Err(ScenarioIrError::DuplicateComponentId { id });
            }
            for name in component.slots.keys() {
                ensure_name_no_dot(name)?;
            }
            for name in component.provides.keys() {
                ensure_name_no_dot(name)?;
            }
            components[id] = Some(component.into_component());
        }

        ensure_component(&components, ir.root, || "root".to_string())?;

        for component in components.iter().flatten() {
            if let Some(parent) = component.parent {
                ensure_component(&components, parent.0, || {
                    format!("parent of component {}", component.id.0)
                })?;
            }
            for child in &component.children {
                ensure_component(&components, child.0, || {
                    format!("child of component {}", component.id.0)
                })?;
            }
        }

        for binding in &ir.bindings {
            if let Some(name) = binding.name.as_deref() {
                ensure_name_no_dot(name)?;
            }
            ensure_name_no_dot(&binding.to.slot)?;
            match &binding.from {
                BindingFromIr::Component { provide, .. } => {
                    ensure_name_no_dot(provide)?;
                }
                BindingFromIr::Framework { capability } => {
                    ensure_name_no_dot(capability)?;
                }
            }
            if let BindingFromIr::Component { component, .. } = &binding.from {
                ensure_component(&components, *component, || {
                    format!("binding source for {}", binding.to.slot)
                })?;
            }
            ensure_component(&components, binding.to.component, || {
                format!("binding target for {}", binding.to.slot)
            })?;
        }
        for export in &ir.exports {
            ensure_name_no_dot(&export.name)?;
            ensure_name_no_dot(&export.from.provide)?;
            ensure_component(&components, export.from.component, || {
                format!("export source for {}", export.name)
            })?;
        }

        let mut scenario = Scenario {
            root: ComponentId(ir.root),
            components,
            bindings: ir
                .bindings
                .into_iter()
                .map(BindingIr::into_binding)
                .collect::<Result<Vec<_>, _>>()?,
            exports: ir.exports.into_iter().map(ExportIr::into_export).collect(),
        };
        scenario.normalize_order();
        Ok(scenario)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComponentIr {
    pub id: usize,
    pub moniker: String,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    pub digest: ManifestDigest,
    pub config: Option<Value>,
    #[serde(default)]
    pub program: Option<Program>,
    #[serde(default)]
    pub slots: BTreeMap<String, SlotDecl>,
    #[serde(default)]
    pub provides: BTreeMap<String, ProvideDecl>,
}

impl ComponentIr {
    fn from_component(id: ComponentId, component: &Component) -> Self {
        Self {
            id: id.0,
            moniker: component.moniker.to_string(),
            parent: component.parent.map(|id| id.0),
            children: component.children.iter().map(|id| id.0).collect(),
            digest: component.digest,
            config: component.config.clone(),
            program: component.program.clone(),
            slots: component.slots.clone(),
            provides: component.provides.clone(),
        }
    }

    fn into_component(self) -> Component {
        Component {
            id: ComponentId(self.id),
            parent: self.parent.map(ComponentId),
            moniker: Moniker::from(self.moniker),
            digest: self.digest,
            config: self.config,
            program: self.program,
            slots: self.slots,
            provides: self.provides,
            children: self.children.into_iter().map(ComponentId).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum BindingFromIr {
    Component { component: usize, provide: String },
    Framework { capability: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindingIr {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub from: BindingFromIr,
    pub to: SlotRefIr,
    pub weak: bool,
}

impl From<&BindingEdge> for BindingIr {
    fn from(binding: &BindingEdge) -> Self {
        Self {
            name: binding.name.clone(),
            from: BindingFromIr::from(&binding.from),
            to: SlotRefIr::from(&binding.to),
            weak: binding.weak,
        }
    }
}

impl BindingIr {
    fn into_binding(self) -> Result<BindingEdge, ScenarioIrError> {
        Ok(BindingEdge {
            name: self.name,
            from: self.from.into_binding_from()?,
            to: self.to.into_slot_ref(),
            weak: self.weak,
        })
    }
}

impl From<&BindingFrom> for BindingFromIr {
    fn from(from: &BindingFrom) -> Self {
        match from {
            BindingFrom::Component(provide) => Self::Component {
                component: provide.component.0,
                provide: provide.name.clone(),
            },
            BindingFrom::Framework(name) => Self::Framework {
                capability: name.to_string(),
            },
        }
    }
}

impl BindingFromIr {
    fn into_binding_from(self) -> Result<BindingFrom, ScenarioIrError> {
        match self {
            BindingFromIr::Component { component, provide } => {
                Ok(BindingFrom::Component(ProvideRef {
                    component: ComponentId(component),
                    name: provide,
                }))
            }
            BindingFromIr::Framework { capability } => {
                let name =
                    FrameworkCapabilityName::try_from(capability.as_str()).map_err(|_| {
                        ScenarioIrError::InvalidName {
                            name: capability.clone(),
                        }
                    })?;
                Ok(BindingFrom::Framework(name))
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProvideRefIr {
    pub component: usize,
    pub provide: String,
}

impl From<&ProvideRef> for ProvideRefIr {
    fn from(provide: &ProvideRef) -> Self {
        Self {
            component: provide.component.0,
            provide: provide.name.clone(),
        }
    }
}

impl ProvideRefIr {
    fn into_provide_ref(self) -> ProvideRef {
        ProvideRef {
            component: ComponentId(self.component),
            name: self.provide,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SlotRefIr {
    pub component: usize,
    pub slot: String,
}

impl From<&SlotRef> for SlotRefIr {
    fn from(slot: &SlotRef) -> Self {
        Self {
            component: slot.component.0,
            slot: slot.name.clone(),
        }
    }
}

impl SlotRefIr {
    fn into_slot_ref(self) -> SlotRef {
        SlotRef {
            component: ComponentId(self.component),
            name: self.slot,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExportIr {
    pub name: String,
    pub capability: CapabilityDecl,
    pub from: ProvideRefIr,
}

impl From<&ScenarioExport> for ExportIr {
    fn from(export: &ScenarioExport) -> Self {
        Self {
            name: export.name.clone(),
            capability: export.capability.clone(),
            from: ProvideRefIr::from(&export.from),
        }
    }
}

impl ExportIr {
    fn into_export(self) -> ScenarioExport {
        ScenarioExport {
            name: self.name,
            capability: self.capability,
            from: self.from.into_provide_ref(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScenarioIrError {
    #[error("scenario IR schema mismatch: expected {expected}, got {actual}")]
    SchemaMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("scenario IR version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },
    #[error("scenario IR has duplicate component id {id}")]
    DuplicateComponentId { id: usize },
    #[error("scenario IR missing component {id} referenced by {context}")]
    MissingComponent { id: usize, context: String },
    #[error("scenario IR has invalid name {name:?}: dots are reserved")]
    InvalidName { name: String },
}

fn ensure_component(
    components: &[Option<Component>],
    id: usize,
    context: impl FnOnce() -> String,
) -> Result<(), ScenarioIrError> {
    let exists = components
        .get(id)
        .and_then(|component| component.as_ref())
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(ScenarioIrError::MissingComponent {
            id,
            context: context(),
        })
    }
}

fn ensure_name_no_dot(name: &str) -> Result<(), ScenarioIrError> {
    if name.contains('.') {
        return Err(ScenarioIrError::InvalidName {
            name: name.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use amber_manifest::{FrameworkCapabilityName, ManifestDigest};
    use serde_json::json;

    use super::{SCENARIO_IR_SCHEMA, SCENARIO_IR_VERSION, ScenarioIr};
    use crate::{
        BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, Scenario,
        ScenarioExport, SlotRef,
    };

    #[test]
    fn scenario_ir_serializes_v1_shape() {
        let components = vec![
            Some(Component {
                id: ComponentId(0),
                parent: None,
                moniker: Moniker::from("/".to_string()),
                digest: ManifestDigest::new([0u8; 32]),
                config: None,
                program: None,
                slots: BTreeMap::new(),
                provides: BTreeMap::new(),
                children: vec![ComponentId(1)],
            }),
            Some(Component {
                id: ComponentId(1),
                parent: Some(ComponentId(0)),
                moniker: Moniker::from("/child".to_string()),
                digest: ManifestDigest::new([1u8; 32]),
                config: None,
                program: Some(
                    serde_json::from_value(json!({
                        "image": "example/child",
                        "network": {
                            "endpoints": [
                                {
                                    "name": "api",
                                    "port": 80,
                                    "protocol": "http"
                                }
                            ]
                        }
                    }))
                    .expect("deserialize program"),
                ),
                slots: BTreeMap::from([(
                    "input".to_string(),
                    serde_json::from_value(json!({
                        "kind": "mcp"
                    }))
                    .expect("deserialize slot decl"),
                )]),
                provides: BTreeMap::from([(
                    "api".to_string(),
                    serde_json::from_value(json!({
                        "kind": "http",
                        "endpoint": "api"
                    }))
                    .expect("deserialize provide decl"),
                )]),
                children: Vec::new(),
            }),
        ];

        let mut scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: vec![BindingEdge {
                name: Some("bind_api".to_string()),
                from: BindingFrom::Component(ProvideRef {
                    component: ComponentId(1),
                    name: "api".to_string(),
                }),
                to: SlotRef {
                    component: ComponentId(0),
                    name: "needs".to_string(),
                },
                weak: false,
            }],
            exports: vec![ScenarioExport {
                name: "api".to_string(),
                capability: serde_json::from_value(json!({
                    "kind": "http"
                }))
                .expect("deserialize capability decl"),
                from: ProvideRef {
                    component: ComponentId(1),
                    name: "api".to_string(),
                },
            }],
        };
        scenario.normalize_order();

        let ir = ScenarioIr::from(&scenario);
        let value = serde_json::to_value(&ir).expect("serialize scenario IR");

        let expected = json!({
            "schema": SCENARIO_IR_SCHEMA,
            "version": SCENARIO_IR_VERSION,
            "root": 0,
            "components": [
                {
                    "id": 0,
                    "moniker": "/",
                    "parent": null,
                    "children": [1],
                    "digest": ManifestDigest::new([0u8; 32]).to_string(),
                    "config": null,
                    "program": null,
                    "slots": {},
                    "provides": {}
                },
                {
                    "id": 1,
                    "moniker": "/child",
                    "parent": 0,
                    "children": [],
                    "digest": ManifestDigest::new([1u8; 32]).to_string(),
                    "config": null,
                    "program": {
                        "image": "example/child",
                        "args": [],
                        "env": {},
                        "network": {
                            "endpoints": [
                                {
                                    "name": "api",
                                    "port": 80,
                                    "protocol": "http"
                                }
                            ]
                        }
                    },
                    "slots": {
                        "input": {
                            "kind": "mcp",
                            "profile": null,
                            "optional": false
                        }
                    },
                    "provides": {
                        "api": {
                            "kind": "http",
                            "profile": null,
                            "endpoint": "api"
                        }
                    }
                }
            ],
            "bindings": [
                {
                    "name": "bind_api",
                    "from": {
                        "kind": "component",
                        "component": 1,
                        "provide": "api"
                    },
                    "to": {
                        "component": 0,
                        "slot": "needs"
                    },
                    "weak": false
                }
            ],
            "exports": [
                {
                    "name": "api",
                    "capability": {
                        "kind": "http",
                        "profile": null
                    },
                    "from": {
                        "component": 1,
                        "provide": "api"
                    }
                }
            ]
        });

        assert_eq!(value, expected);
    }

    #[test]
    fn scenario_ir_defaults_missing_program_and_caps() {
        let payload = json!({
            "schema": SCENARIO_IR_SCHEMA,
            "version": SCENARIO_IR_VERSION,
            "root": 0,
            "components": [
                {
                    "id": 0,
                    "moniker": "/",
                    "parent": null,
                    "children": [],
                    "digest": ManifestDigest::new([0u8; 32]).to_string(),
                    "config": null
                }
            ],
            "bindings": [],
            "exports": []
        });

        let ir: ScenarioIr = serde_json::from_value(payload).expect("deserialize scenario IR");
        let scenario: Scenario = ir.try_into().expect("convert scenario IR");
        let root = scenario.component(ComponentId(0));

        assert!(root.program.is_none());
        assert!(root.slots.is_empty());
        assert!(root.provides.is_empty());
    }

    #[test]
    fn scenario_ir_roundtrips_framework_binding() {
        let components = vec![Some(Component {
            id: ComponentId(0),
            parent: None,
            moniker: Moniker::from("/".to_string()),
            digest: ManifestDigest::new([0u8; 32]),
            config: None,
            program: None,
            slots: BTreeMap::new(),
            provides: BTreeMap::new(),
            children: Vec::new(),
        })];

        let mut scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: vec![BindingEdge {
                name: None,
                from: BindingFrom::Framework(
                    FrameworkCapabilityName::try_from("dynamic_children").unwrap(),
                ),
                to: SlotRef {
                    component: ComponentId(0),
                    name: "control".to_string(),
                },
                weak: false,
            }],
            exports: Vec::new(),
        };
        scenario.normalize_order();

        let ir = ScenarioIr::from(&scenario);
        let value = serde_json::to_value(&ir).expect("serialize scenario IR");

        assert_eq!(
            value["bindings"][0]["from"]["kind"],
            serde_json::Value::String("framework".to_string())
        );
        assert_eq!(
            value["bindings"][0]["from"]["capability"],
            serde_json::Value::String("dynamic_children".to_string())
        );

        let roundtripped: Scenario = ir.try_into().expect("deserialize scenario IR");
        let binding = &roundtripped.bindings[0];
        match &binding.from {
            BindingFrom::Framework(name) => assert_eq!(name.as_str(), "dynamic_children"),
            BindingFrom::Component(_) => panic!("expected framework binding"),
        }
    }

    #[test]
    fn scenario_ir_rejects_framework_capability_with_dot() {
        let payload = json!({
            "schema": SCENARIO_IR_SCHEMA,
            "version": SCENARIO_IR_VERSION,
            "root": 0,
            "components": [
                {
                    "id": 0,
                    "moniker": "/",
                    "parent": null,
                    "children": [],
                    "digest": ManifestDigest::new([0u8; 32]).to_string(),
                    "config": null
                }
            ],
            "bindings": [
                {
                    "from": { "kind": "framework", "capability": "bad.name" },
                    "to": { "component": 0, "slot": "control" },
                    "weak": false
                }
            ],
            "exports": []
        });

        let ir: ScenarioIr = serde_json::from_value(payload).expect("deserialize scenario IR");
        let err = Scenario::try_from(ir).expect_err("invalid name");
        let message = err.to_string();
        assert!(message.contains("invalid name"), "{message}");
        assert!(message.contains("dots are reserved"), "{message}");
    }

    #[test]
    fn scenario_ir_rejects_binding_name_with_dot() {
        let payload = json!({
            "schema": SCENARIO_IR_SCHEMA,
            "version": SCENARIO_IR_VERSION,
            "root": 0,
            "components": [
                {
                    "id": 0,
                    "moniker": "/",
                    "parent": null,
                    "children": [],
                    "digest": ManifestDigest::new([0u8; 32]).to_string(),
                    "config": null
                }
            ],
            "bindings": [
                {
                    "name": "bad.name",
                    "from": { "kind": "component", "component": 0, "provide": "api" },
                    "to": { "component": 0, "slot": "needs" },
                    "weak": false
                }
            ],
            "exports": []
        });

        let ir: ScenarioIr = serde_json::from_value(payload).expect("deserialize scenario IR");
        let err = Scenario::try_from(ir).expect_err("invalid name");
        let message = err.to_string();
        assert!(message.contains("invalid name"), "{message}");
        assert!(message.contains("dots are reserved"), "{message}");
    }

    #[test]
    fn scenario_ir_binding_name_round_trip() {
        let payload = json!({
            "schema": SCENARIO_IR_SCHEMA,
            "version": SCENARIO_IR_VERSION,
            "root": 0,
            "components": [
                {
                    "id": 0,
                    "moniker": "/",
                    "parent": null,
                    "children": [1],
                    "digest": ManifestDigest::new([0u8; 32]).to_string(),
                    "config": null
                },
                {
                    "id": 1,
                    "moniker": "/child",
                    "parent": 0,
                    "children": [],
                    "digest": ManifestDigest::new([1u8; 32]).to_string(),
                    "config": null
                }
            ],
            "bindings": [
                {
                    "name": "route",
                    "from": { "kind": "component", "component": 1, "provide": "api" },
                    "to": { "component": 0, "slot": "needs" },
                    "weak": false
                }
            ],
            "exports": []
        });

        let ir: ScenarioIr = serde_json::from_value(payload).expect("deserialize scenario IR");
        let scenario: Scenario = ir.try_into().expect("convert scenario IR");
        assert_eq!(scenario.bindings[0].name.as_deref(), Some("route"));
    }
}
