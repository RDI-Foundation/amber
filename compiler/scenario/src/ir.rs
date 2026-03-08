use std::collections::BTreeMap;

use amber_manifest::{
    CapabilityDecl, FrameworkCapabilityName, ManifestDigest, Program, ProvideDecl, SlotDecl,
    framework_capability,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, ResourceDecl,
    ResourceRef, Scenario, ScenarioExport, SlotRef,
};

pub const SCENARIO_IR_SCHEMA: &str = "amber.scenario.ir";
pub const SCENARIO_IR_VERSION: u32 = 2;
const MIN_SCENARIO_IR_VERSION: u32 = 1;

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
        if !(MIN_SCENARIO_IR_VERSION..=SCENARIO_IR_VERSION).contains(&ir.version) {
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
            for name in component.resources.keys() {
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

        for component in components.iter().flatten() {
            for (name, slot) in &component.binding_decls {
                ensure_name_no_dot(name)?;
                ensure_name_no_dot(&slot.name)?;
                let context = format!(
                    "binding declaration `{name}` in component {} (id {})",
                    component.moniker.as_str(),
                    component.id.0
                );
                ensure_component(&components, slot.component.0, || context.clone())?;
                ensure_slot(&components, slot.component, &slot.name, || context.clone())?;
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
                BindingFromIr::Resource { resource, .. } => {
                    ensure_name_no_dot(resource)?;
                }
                BindingFromIr::Framework { capability } => {
                    ensure_name_no_dot(capability)?;
                }
                BindingFromIr::External { slot } => {
                    ensure_name_no_dot(&slot.slot)?;
                    ensure_component(&components, slot.component, || {
                        format!("external slot source for {}", binding.to.slot)
                    })?;
                }
            }
            if let BindingFromIr::Component { component, .. } = &binding.from {
                ensure_component(&components, *component, || {
                    format!("binding source for {}", binding.to.slot)
                })?;
            }
            if let BindingFromIr::Resource {
                component,
                resource,
                ..
            } = &binding.from
            {
                ensure_component(&components, *component, || {
                    format!("binding resource source for {}", binding.to.slot)
                })?;
                let owner = components[*component]
                    .as_ref()
                    .expect("resource owner component should exist");
                if !owner.resources.contains_key(resource) {
                    return Err(ScenarioIrError::MissingResource {
                        component: *component,
                        component_moniker: owner.moniker.to_string(),
                        resource: resource.clone(),
                        context: format!("binding source for {}", binding.to.slot),
                    });
                }
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
        validate_scenario(&scenario)?;
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
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_url: Option<String>,
    pub digest: ManifestDigest,
    pub config: Option<Value>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_schema: Option<Value>,
    #[serde(default)]
    pub program: Option<Program>,
    #[serde(default)]
    pub slots: BTreeMap<String, SlotDecl>,
    #[serde(default)]
    pub provides: BTreeMap<String, ProvideDecl>,
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, ResourceDecl>,
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub binding_decls: BTreeMap<String, SlotRefIr>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

impl ComponentIr {
    fn from_component(id: ComponentId, component: &Component) -> Self {
        Self {
            id: id.0,
            moniker: component.moniker.to_string(),
            parent: component.parent.map(|id| id.0),
            children: component.children.iter().map(|id| id.0).collect(),
            resolved_url: None,
            digest: component.digest,
            config: component.config.clone(),
            config_schema: component.config_schema.clone(),
            program: component.program.clone(),
            slots: component.slots.clone(),
            provides: component.provides.clone(),
            resources: component.resources.clone(),
            binding_decls: component
                .binding_decls
                .iter()
                .map(|(name, slot)| (name.clone(), SlotRefIr::from(slot)))
                .collect(),
            metadata: component.metadata.clone(),
        }
    }

    fn into_component(self) -> Component {
        Component {
            id: ComponentId(self.id),
            parent: self.parent.map(ComponentId),
            moniker: Moniker::from(self.moniker),
            digest: self.digest,
            config: self.config,
            config_schema: self.config_schema,
            program: self.program,
            slots: self.slots,
            provides: self.provides,
            resources: self.resources,
            binding_decls: self
                .binding_decls
                .into_iter()
                .map(|(name, slot)| (name, slot.into_slot_ref()))
                .collect(),
            metadata: self.metadata,
            children: self.children.into_iter().map(ComponentId).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum BindingFromIr {
    Component { component: usize, provide: String },
    Resource { component: usize, resource: String },
    Framework { capability: String },
    External { slot: SlotRefIr },
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
            BindingFrom::Resource(resource) => Self::Resource {
                component: resource.component.0,
                resource: resource.name.clone(),
            },
            BindingFrom::Framework(name) => Self::Framework {
                capability: name.to_string(),
            },
            BindingFrom::External(slot) => Self::External {
                slot: SlotRefIr::from(slot),
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
            BindingFromIr::Resource {
                component,
                resource,
            } => Ok(BindingFrom::Resource(ResourceRef {
                component: ComponentId(component),
                name: resource,
            })),
            BindingFromIr::Framework { capability } => {
                let name =
                    FrameworkCapabilityName::try_from(capability.as_str()).map_err(|_| {
                        ScenarioIrError::InvalidName {
                            name: capability.clone(),
                        }
                    })?;
                Ok(BindingFrom::Framework(name))
            }
            BindingFromIr::External { slot } => Ok(BindingFrom::External(slot.into_slot_ref())),
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
    #[error(
        "{context} targets missing slot {slot:?} on component {component_moniker} (id {component})"
    )]
    MissingSlot {
        component: usize,
        component_moniker: String,
        slot: String,
        context: String,
    },
    #[error(
        "{context} targets missing provide {provide:?} on component {component_moniker} (id \
         {component})"
    )]
    MissingProvide {
        component: usize,
        component_moniker: String,
        provide: String,
        context: String,
    },
    #[error(
        "{context} references missing resource {resource:?} on component {component_moniker} (id \
         {component})"
    )]
    MissingResource {
        component: usize,
        component_moniker: String,
        resource: String,
        context: String,
    },
    #[error("scenario IR has invalid name {name:?}: dots are reserved")]
    InvalidName { name: String },
    #[error("scenario IR is invalid: {message}")]
    InvalidScenario { message: String },
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

fn component_ref(
    components: &[Option<Component>],
    id: ComponentId,
    context: impl FnOnce() -> String,
) -> Result<&Component, ScenarioIrError> {
    let context = context();
    ensure_component(components, id.0, || context.clone())?;
    Ok(components[id.0]
        .as_ref()
        .expect("component existence was checked above"))
}

fn ensure_slot<'a>(
    components: &'a [Option<Component>],
    component: ComponentId,
    slot: &str,
    context: impl FnOnce() -> String,
) -> Result<&'a SlotDecl, ScenarioIrError> {
    let context = context();
    let target = component_ref(components, component, || context.clone())?;
    if target.slots.contains_key(slot) {
        Ok(target
            .slots
            .get(slot)
            .expect("slot existence was checked above"))
    } else {
        Err(ScenarioIrError::MissingSlot {
            component: component.0,
            component_moniker: target.moniker.to_string(),
            slot: slot.to_string(),
            context,
        })
    }
}

fn ensure_provide<'a>(
    components: &'a [Option<Component>],
    component: ComponentId,
    provide: &str,
    context: impl FnOnce() -> String,
) -> Result<&'a ProvideDecl, ScenarioIrError> {
    let context = context();
    let target = component_ref(components, component, || context.clone())?;
    if target.provides.contains_key(provide) {
        Ok(target
            .provides
            .get(provide)
            .expect("provide existence was checked above"))
    } else {
        Err(ScenarioIrError::MissingProvide {
            component: component.0,
            component_moniker: target.moniker.to_string(),
            provide: provide.to_string(),
            context,
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

fn invalid_scenario(message: impl Into<String>) -> ScenarioIrError {
    ScenarioIrError::InvalidScenario {
        message: message.into(),
    }
}

fn validate_scenario(scenario: &Scenario) -> Result<(), ScenarioIrError> {
    validate_component_tree(scenario)?;
    validate_bindings(scenario)?;
    validate_exports(scenario)?;
    Ok(())
}

fn validate_component_tree(scenario: &Scenario) -> Result<(), ScenarioIrError> {
    let root = component_ref(&scenario.components, scenario.root, || "root".to_string())?;
    if let Some(parent) = root.parent {
        return Err(invalid_scenario(format!(
            "root component {} (id {}) unexpectedly has parent {}",
            root.moniker.as_str(),
            scenario.root.0,
            parent.0
        )));
    }

    for (idx, component) in scenario
        .components
        .iter()
        .enumerate()
        .filter_map(|(idx, component)| component.as_ref().map(|component| (idx, component)))
    {
        if component.id != ComponentId(idx) {
            return Err(invalid_scenario(format!(
                "component slot {idx} stores component id {}",
                component.id.0
            )));
        }

        for name in component.slots.keys() {
            ensure_name_no_dot(name)?;
        }
        for name in component.provides.keys() {
            ensure_name_no_dot(name)?;
        }
        for (name, slot) in &component.binding_decls {
            ensure_name_no_dot(name)?;
            ensure_name_no_dot(&slot.name)?;
            let context = format!(
                "binding declaration `{name}` in component {} (id {})",
                component.moniker.as_str(),
                component.id.0
            );
            ensure_slot(&scenario.components, slot.component, &slot.name, || {
                context.clone()
            })?;
        }

        if component.id != scenario.root {
            let Some(parent) = component.parent else {
                return Err(invalid_scenario(format!(
                    "component {} (id {}) is not attached to the root component",
                    component.moniker.as_str(),
                    component.id.0
                )));
            };
            let parent_component = component_ref(&scenario.components, parent, || {
                format!("parent of component {}", component.id.0)
            })?;
            if !parent_component.children.contains(&component.id) {
                return Err(invalid_scenario(format!(
                    "component {} (id {}) claims parent {} (id {}), but the parent does not list \
                     it as a child",
                    component.moniker.as_str(),
                    component.id.0,
                    parent_component.moniker.as_str(),
                    parent.0
                )));
            }
        }

        let mut seen_children = std::collections::HashSet::new();
        for child in &component.children {
            let child_component = component_ref(&scenario.components, *child, || {
                format!("child of component {}", component.id.0)
            })?;
            if !seen_children.insert(*child) {
                return Err(invalid_scenario(format!(
                    "component {} (id {}) lists child {} (id {}) more than once",
                    component.moniker.as_str(),
                    component.id.0,
                    child_component.moniker.as_str(),
                    child.0
                )));
            }
            if child_component.parent != Some(component.id) {
                let actual_parent = child_component
                    .parent
                    .map(|parent| parent.0.to_string())
                    .unwrap_or_else(|| "none".to_string());
                return Err(invalid_scenario(format!(
                    "component {} (id {}) lists {} (id {}) as a child, but that component records \
                     parent {actual_parent}",
                    component.moniker.as_str(),
                    component.id.0,
                    child_component.moniker.as_str(),
                    child.0
                )));
            }
        }
    }

    for component in scenario.components.iter().flatten() {
        if component.id == scenario.root {
            continue;
        }
        let mut seen = std::collections::HashSet::new();
        let mut cur = component.id;
        while cur != scenario.root {
            if !seen.insert(cur) {
                return Err(invalid_scenario(format!(
                    "component {} (id {}) participates in a containment cycle",
                    component.moniker.as_str(),
                    component.id.0
                )));
            }
            let cur_component = component_ref(&scenario.components, cur, || {
                format!("ancestor of component {}", component.id.0)
            })?;
            let Some(parent) = cur_component.parent else {
                return Err(invalid_scenario(format!(
                    "component {} (id {}) is not attached to the root component",
                    component.moniker.as_str(),
                    component.id.0
                )));
            };
            cur = parent;
        }
    }

    Ok(())
}

fn validate_bindings(scenario: &Scenario) -> Result<(), ScenarioIrError> {
    for binding in &scenario.bindings {
        if let Some(name) = binding.name.as_deref() {
            ensure_name_no_dot(name)?;
        }
        ensure_name_no_dot(&binding.to.name)?;

        let target_label = format!(
            "{}.{}",
            component_ref(&scenario.components, binding.to.component, || {
                format!("binding target for {}", binding.to.name)
            })?
            .moniker
            .as_str(),
            binding.to.name
        );
        let target_decl = ensure_slot(
            &scenario.components,
            binding.to.component,
            &binding.to.name,
            || format!("binding target for {}", binding.to.name),
        )?
        .decl
        .clone();

        let (source_label, source_decl) = match &binding.from {
            BindingFrom::Component(provide) => {
                ensure_name_no_dot(&provide.name)?;
                let provide_decl = ensure_provide(
                    &scenario.components,
                    provide.component,
                    &provide.name,
                    || format!("binding source for {}", binding.to.name),
                )?;
                let component = component_ref(&scenario.components, provide.component, || {
                    format!("binding source for {}", binding.to.name)
                })?;
                (
                    format!("{}.{}", component.moniker.as_str(), provide.name),
                    provide_decl.decl.clone(),
                )
            }
            BindingFrom::Resource(resource) => {
                ensure_name_no_dot(&resource.name)?;
                let component = component_ref(&scenario.components, resource.component, || {
                    format!("binding source for {}", binding.to.name)
                })?;
                let resource_decl =
                    component
                        .resources
                        .get(resource.name.as_str())
                        .ok_or_else(|| {
                            invalid_scenario(format!(
                                "binding into {target_label} references missing resource \
                                 {}.resources.{}",
                                component.moniker.as_str(),
                                resource.name
                            ))
                        })?;
                (
                    format!("{}.resources.{}", component.moniker.as_str(), resource.name),
                    CapabilityDecl::builder().kind(resource_decl.kind).build(),
                )
            }
            BindingFrom::Framework(name) => {
                let spec = framework_capability(name.as_str()).ok_or_else(|| {
                    invalid_scenario(format!(
                        "binding into {target_label} references unknown framework capability \
                         `framework.{name}`"
                    ))
                })?;
                (format!("framework.{name}"), spec.decl.clone())
            }
            BindingFrom::External(slot) => {
                ensure_name_no_dot(&slot.name)?;
                if !binding.weak {
                    return Err(invalid_scenario(format!(
                        "binding into {target_label} must be weak because it depends on external \
                         slot `{}`",
                        slot.name
                    )));
                }
                if slot.component != scenario.root {
                    let actual_component =
                        component_ref(&scenario.components, slot.component, || {
                            format!("external slot source for {}", binding.to.name)
                        })?;
                    let root_component =
                        component_ref(&scenario.components, scenario.root, || "root".to_string())?;
                    return Err(invalid_scenario(format!(
                        "binding into {target_label} references external slot {}.{} (id {}), but \
                         external bindings must point to slots declared on root component {} (id \
                         {})",
                        actual_component.moniker.as_str(),
                        slot.name,
                        slot.component.0,
                        root_component.moniker.as_str(),
                        scenario.root.0
                    )));
                }
                let slot_decl =
                    ensure_slot(&scenario.components, scenario.root, &slot.name, || {
                        format!("external slot source for {}", binding.to.name)
                    })?;
                let root_component =
                    component_ref(&scenario.components, scenario.root, || "root".to_string())?;
                (
                    format!("external {}.{}", root_component.moniker.as_str(), slot.name),
                    slot_decl.decl.clone(),
                )
            }
        };

        if source_decl != target_decl {
            return Err(invalid_scenario(format!(
                "binding into {target_label} expects {target_decl}, but {source_label} provides \
                 {source_decl}"
            )));
        }
    }

    Ok(())
}

fn validate_exports(scenario: &Scenario) -> Result<(), ScenarioIrError> {
    let mut export_names = std::collections::HashSet::new();
    for export in &scenario.exports {
        ensure_name_no_dot(&export.name)?;
        ensure_name_no_dot(&export.from.name)?;
        if !export_names.insert(export.name.clone()) {
            return Err(invalid_scenario(format!(
                "scenario export `{}` is declared more than once",
                export.name
            )));
        }

        let provide = ensure_provide(
            &scenario.components,
            export.from.component,
            &export.from.name,
            || format!("export source for {}", export.name),
        )?;
        let component = component_ref(&scenario.components, export.from.component, || {
            format!("export source for {}", export.name)
        })?;
        if provide.decl != export.capability {
            return Err(invalid_scenario(format!(
                "scenario export `{}` declares capability {}, but {}.{} provides {}",
                export.name,
                export.capability,
                component.moniker.as_str(),
                export.from.name,
                provide.decl
            )));
        }
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

    fn slot_decl(kind: &str) -> amber_manifest::SlotDecl {
        serde_json::from_value(json!({ "kind": kind })).expect("deserialize slot decl")
    }

    #[test]
    fn scenario_ir_serializes_v2_shape() {
        let components = vec![
            Some(Component {
                id: ComponentId(0),
                parent: None,
                moniker: Moniker::from("/".to_string()),
                digest: ManifestDigest::new([0u8; 32]),
                config: None,
                config_schema: None,
                program: None,
                slots: BTreeMap::new(),
                provides: BTreeMap::new(),
                resources: BTreeMap::new(),
                binding_decls: BTreeMap::new(),
                metadata: None,
                children: vec![ComponentId(1)],
            }),
            Some(Component {
                id: ComponentId(1),
                parent: Some(ComponentId(0)),
                moniker: Moniker::from("/child".to_string()),
                digest: ManifestDigest::new([1u8; 32]),
                config: None,
                config_schema: None,
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
                resources: BTreeMap::new(),
                binding_decls: BTreeMap::new(),
                metadata: None,
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
                        "entrypoint": [],
                        "env": {},
                        "mounts": [],
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
    fn scenario_ir_accepts_v1_inputs() {
        let ir = json!({
            "schema": SCENARIO_IR_SCHEMA,
            "version": 1,
            "root": 0,
            "components": [
                {
                    "id": 0,
                    "moniker": "/",
                    "parent": null,
                    "children": [],
                    "digest": ManifestDigest::new([0u8; 32]).to_string(),
                    "config": null,
                    "program": null,
                    "slots": {},
                    "provides": {}
                }
            ],
            "bindings": [],
            "exports": []
        });

        let parsed: ScenarioIr =
            serde_json::from_value(ir).expect("deserialize legacy scenario IR");
        let scenario =
            Scenario::try_from(parsed).expect("legacy scenario IR should remain accepted");
        assert_eq!(scenario.root, ComponentId(0));
        assert_eq!(scenario.components_iter().count(), 1);
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
            config_schema: None,
            program: None,
            slots: BTreeMap::from([("docker".to_string(), slot_decl("docker"))]),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            binding_decls: BTreeMap::new(),
            metadata: None,
            children: Vec::new(),
        })];

        let mut scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: vec![BindingEdge {
                name: None,
                from: BindingFrom::Framework(FrameworkCapabilityName::try_from("docker").unwrap()),
                to: SlotRef {
                    component: ComponentId(0),
                    name: "docker".to_string(),
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
            serde_json::Value::String("docker".to_string())
        );

        let roundtripped: Scenario = ir.try_into().expect("deserialize scenario IR");
        let binding = &roundtripped.bindings[0];
        match &binding.from {
            BindingFrom::Framework(name) => assert_eq!(name.as_str(), "docker"),
            BindingFrom::Component(_) => panic!("expected framework binding"),
            BindingFrom::Resource(resource) => {
                panic!("unexpected resource binding resources.{}", resource.name)
            }
            BindingFrom::External(slot) => {
                panic!("unexpected external binding slots.{}", slot.name)
            }
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
                    "config": null,
                    "slots": {
                        "docker": { "kind": "docker" }
                    }
                }
            ],
            "bindings": [
                {
                    "from": { "kind": "framework", "capability": "bad.name" },
                    "to": { "component": 0, "slot": "docker" },
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
                    "config": null,
                    "slots": {
                        "needs": { "kind": "http" }
                    },
                    "provides": {
                        "api": { "kind": "http", "endpoint": "api" }
                    }
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
    fn scenario_ir_rejects_binding_decl_missing_slot() {
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
                    "config": null,
                    "binding_decls": {
                        "bind": { "component": 1, "slot": "api" }
                    }
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
            "bindings": [],
            "exports": []
        });

        let ir: ScenarioIr = serde_json::from_value(payload).expect("deserialize scenario IR");
        let err = Scenario::try_from(ir).expect_err("invalid binding decl");
        let message = err.to_string();
        assert!(message.contains("binding declaration"), "{message}");
        assert!(message.contains("targets missing slot"), "{message}");
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
                    "config": null,
                    "slots": {
                        "needs": { "kind": "http" }
                    }
                },
                {
                    "id": 1,
                    "moniker": "/child",
                    "parent": 0,
                    "children": [],
                    "digest": ManifestDigest::new([1u8; 32]).to_string(),
                    "config": null,
                    "provides": {
                        "api": { "kind": "http", "endpoint": "api" }
                    }
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

    #[test]
    fn scenario_ir_rejects_binding_target_missing_slot() {
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
                    "config": null,
                    "provides": {
                        "api": { "kind": "http", "endpoint": "api" }
                    }
                }
            ],
            "bindings": [
                {
                    "from": { "kind": "component", "component": 1, "provide": "api" },
                    "to": { "component": 0, "slot": "needs" },
                    "weak": false
                }
            ],
            "exports": []
        });

        let ir: ScenarioIr = serde_json::from_value(payload).expect("deserialize scenario IR");
        let err = Scenario::try_from(ir).expect_err("missing target slot");
        let message = err.to_string();
        assert!(message.contains("binding target"), "{message}");
        assert!(message.contains("targets missing slot"), "{message}");
    }

    #[test]
    fn scenario_ir_rejects_binding_source_missing_provide() {
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
                    "config": null,
                    "slots": {
                        "needs": { "kind": "http" }
                    }
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
                    "from": { "kind": "component", "component": 1, "provide": "api" },
                    "to": { "component": 0, "slot": "needs" },
                    "weak": false
                }
            ],
            "exports": []
        });

        let ir: ScenarioIr = serde_json::from_value(payload).expect("deserialize scenario IR");
        let err = Scenario::try_from(ir).expect_err("missing provide");
        let message = err.to_string();
        assert!(message.contains("binding source"), "{message}");
        assert!(message.contains("targets missing provide"), "{message}");
    }

    #[test]
    fn scenario_ir_rejects_external_binding_not_on_root() {
        let payload = json!({
            "schema": SCENARIO_IR_SCHEMA,
            "version": SCENARIO_IR_VERSION,
            "root": 0,
            "components": [
                {
                    "id": 0,
                    "moniker": "/",
                    "parent": null,
                    "children": [1, 2],
                    "digest": ManifestDigest::new([0u8; 32]).to_string(),
                    "config": null
                },
                {
                    "id": 1,
                    "moniker": "/source",
                    "parent": 0,
                    "children": [],
                    "digest": ManifestDigest::new([1u8; 32]).to_string(),
                    "config": null,
                    "slots": {
                        "api": { "kind": "http" }
                    }
                },
                {
                    "id": 2,
                    "moniker": "/client",
                    "parent": 0,
                    "children": [],
                    "digest": ManifestDigest::new([2u8; 32]).to_string(),
                    "config": null,
                    "slots": {
                        "api": { "kind": "http" }
                    }
                }
            ],
            "bindings": [
                {
                    "from": { "kind": "external", "slot": { "component": 1, "slot": "api" } },
                    "to": { "component": 2, "slot": "api" },
                    "weak": true
                }
            ],
            "exports": []
        });

        let ir: ScenarioIr = serde_json::from_value(payload).expect("deserialize scenario IR");
        let err = Scenario::try_from(ir).expect_err("external slot must live on root");
        let message = err.to_string();
        assert!(
            message.contains("external bindings must point to slots declared on root"),
            "{message}"
        );
    }

    #[test]
    fn scenario_ir_rejects_export_capability_mismatch() {
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
                    "config": null,
                    "provides": {
                        "api": { "kind": "http", "endpoint": "api" }
                    }
                }
            ],
            "bindings": [],
            "exports": [
                {
                    "name": "api",
                    "capability": { "kind": "mcp" },
                    "from": { "component": 0, "provide": "api" }
                }
            ]
        });

        let ir: ScenarioIr = serde_json::from_value(payload).expect("deserialize scenario IR");
        let err = Scenario::try_from(ir).expect_err("export capability mismatch");
        let message = err.to_string();
        assert!(
            message.contains("scenario export `api` declares capability mcp"),
            "{message}"
        );
    }
}
