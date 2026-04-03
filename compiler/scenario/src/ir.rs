use std::collections::BTreeMap;

use amber_manifest::{
    CapabilityDecl, CapabilityKind, FrameworkCapabilityName, Manifest, ManifestDigest, ProvideDecl,
    RealmSelector, RuntimeBackend, SlotDecl, framework_capability,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    BindingEdge, BindingFrom, ChildTemplate, ChildTemplateLimits, Component, ComponentId,
    FrameworkRef, ManifestCatalogEntry, Moniker, Program, ProgramMount, ProvideRef, ResourceDecl,
    ResourceRef, Scenario, ScenarioExport, SlotRef, TemplateBinding, TemplateConfigField,
};

pub const SCENARIO_IR_SCHEMA: &str = "amber.scenario.ir";
pub const SCENARIO_IR_VERSION: u32 = 5;
const MIN_SCENARIO_IR_VERSION: u32 = 4;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ScenarioIr {
    pub schema: String,
    pub version: u32,
    pub root: usize,
    pub components: Vec<ComponentIr>,
    pub bindings: Vec<BindingIr>,
    pub exports: Vec<ExportIr>,
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub manifest_catalog: BTreeMap<String, ManifestCatalogEntryIr>,
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
            manifest_catalog: scenario
                .manifest_catalog
                .iter()
                .map(|(key, entry)| (key.clone(), ManifestCatalogEntryIr::from(entry)))
                .collect(),
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
        let mut component_irs = vec![None; max_id + 1];
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
            for name in component.exports.keys() {
                ensure_name_no_dot(name)?;
            }
            for name in component.resources.keys() {
                ensure_name_no_dot(name)?;
            }
            for name in component.child_templates.keys() {
                ensure_name_no_dot(name)?;
            }
            for (name, template) in &component.child_templates {
                match (&template.manifest, &template.allowed_manifests) {
                    (Some(_), None) | (None, Some(_)) => {}
                    (Some(_), Some(_)) => {
                        return Err(invalid_scenario(format!(
                            "child template `{name}` must not specify both `manifest` and \
                             `allowed_manifests`"
                        )));
                    }
                    (None, None) => {
                        return Err(invalid_scenario(format!(
                            "child template `{name}` must specify one of `manifest` or \
                             `allowed_manifests`"
                        )));
                    }
                }
                if template
                    .allowed_manifests
                    .as_ref()
                    .is_some_and(|allowed| allowed.is_empty())
                {
                    return Err(invalid_scenario(format!(
                        "child template `{name}` must not have an empty `allowed_manifests` list"
                    )));
                }
            }
            component_irs[id] = Some(component.clone());
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

        validate_component_exports(&component_irs, &components)?;

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
                BindingFromIr::Framework {
                    capability,
                    authority_realm,
                } => {
                    ensure_name_no_dot(capability)?;
                    ensure_component(&components, *authority_realm, || {
                        format!("framework authority realm for {}", binding.to.slot)
                    })?;
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
            manifest_catalog: ir
                .manifest_catalog
                .into_iter()
                .map(|(key, entry)| (key, entry.into_entry()))
                .collect(),
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
    pub exports: BTreeMap<String, ComponentExportTargetIr>,
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub resources: BTreeMap<String, ResourceDecl>,
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub child_templates: BTreeMap<String, ChildTemplateIr>,
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
            exports: BTreeMap::new(),
            resources: component.resources.clone(),
            child_templates: component
                .child_templates
                .iter()
                .map(|(name, template)| (name.clone(), ChildTemplateIr::from(template)))
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
            child_templates: self
                .child_templates
                .into_iter()
                .map(|(name, template)| (name, template.into_template()))
                .collect(),
            metadata: self.metadata,
            children: self.children.into_iter().map(ComponentId).collect(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "target", rename_all = "snake_case")]
pub enum ComponentExportTargetIr {
    SelfProvide { provide: String },
    SelfSlot { slot: String },
    ChildExport { child: String, export: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChildTemplateIr {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_manifests: Option<Vec<String>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, TemplateConfigFieldIr>,
    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings: BTreeMap<String, TemplateBindingIr>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visible_exports: Option<Vec<String>>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<ChildTemplateLimitsIr>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub possible_backends: Vec<RuntimeBackend>,
}

impl From<&ChildTemplate> for ChildTemplateIr {
    fn from(template: &ChildTemplate) -> Self {
        Self {
            manifest: template.manifest.clone(),
            allowed_manifests: template.allowed_manifests.clone(),
            config: template
                .config
                .iter()
                .map(|(name, field)| (name.clone(), TemplateConfigFieldIr::from(field)))
                .collect(),
            bindings: template
                .bindings
                .iter()
                .map(|(name, field)| (name.clone(), TemplateBindingIr::from(field)))
                .collect(),
            visible_exports: template.visible_exports.clone(),
            limits: template.limits.as_ref().map(ChildTemplateLimitsIr::from),
            possible_backends: template.possible_backends.clone(),
        }
    }
}

impl ChildTemplateIr {
    fn into_template(self) -> ChildTemplate {
        ChildTemplate {
            manifest: self.manifest,
            allowed_manifests: self.allowed_manifests,
            config: self
                .config
                .into_iter()
                .map(|(name, field)| (name, field.into_field()))
                .collect(),
            bindings: self
                .bindings
                .into_iter()
                .map(|(name, field)| (name, field.into_field()))
                .collect(),
            visible_exports: self.visible_exports,
            limits: self.limits.map(ChildTemplateLimitsIr::into_limits),
            possible_backends: self.possible_backends,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TemplateConfigFieldIr {
    Prefilled { value: Value },
    Open { required: bool },
}

impl From<&TemplateConfigField> for TemplateConfigFieldIr {
    fn from(field: &TemplateConfigField) -> Self {
        match field {
            TemplateConfigField::Prefilled { value } => Self::Prefilled {
                value: value.clone(),
            },
            TemplateConfigField::Open { required } => Self::Open {
                required: *required,
            },
        }
    }
}

impl TemplateConfigFieldIr {
    fn into_field(self) -> TemplateConfigField {
        match self {
            Self::Prefilled { value } => TemplateConfigField::Prefilled { value },
            Self::Open { required } => TemplateConfigField::Open { required },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum TemplateBindingIr {
    Prefilled { selector: RealmSelector },
    Open { optional: bool },
}

impl From<&TemplateBinding> for TemplateBindingIr {
    fn from(field: &TemplateBinding) -> Self {
        match field {
            TemplateBinding::Prefilled { selector } => Self::Prefilled {
                selector: selector.clone(),
            },
            TemplateBinding::Open { optional } => Self::Open {
                optional: *optional,
            },
        }
    }
}

impl TemplateBindingIr {
    fn into_field(self) -> TemplateBinding {
        match self {
            Self::Prefilled { selector } => TemplateBinding::Prefilled { selector },
            Self::Open { optional } => TemplateBinding::Open { optional },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChildTemplateLimitsIr {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_live_children: Option<u32>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_pattern: Option<String>,
}

impl From<&ChildTemplateLimits> for ChildTemplateLimitsIr {
    fn from(limits: &ChildTemplateLimits) -> Self {
        Self {
            max_live_children: limits.max_live_children,
            name_pattern: limits.name_pattern.clone(),
        }
    }
}

impl ChildTemplateLimitsIr {
    fn into_limits(self) -> ChildTemplateLimits {
        ChildTemplateLimits {
            max_live_children: self.max_live_children,
            name_pattern: self.name_pattern,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestCatalogEntryIr {
    pub source_ref: String,
    pub digest: ManifestDigest,
    pub manifest: Manifest,
}

impl From<&ManifestCatalogEntry> for ManifestCatalogEntryIr {
    fn from(entry: &ManifestCatalogEntry) -> Self {
        Self {
            source_ref: entry.source_ref.clone(),
            digest: entry.digest,
            manifest: entry.manifest.clone(),
        }
    }
}

impl ManifestCatalogEntryIr {
    fn into_entry(self) -> ManifestCatalogEntry {
        ManifestCatalogEntry {
            source_ref: self.source_ref,
            digest: self.digest,
            manifest: self.manifest,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum BindingFromIr {
    Component {
        component: usize,
        provide: String,
    },
    Resource {
        component: usize,
        resource: String,
    },
    Framework {
        capability: String,
        authority_realm: usize,
    },
    External {
        slot: SlotRefIr,
    },
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
            name: None,
            from: BindingFromIr::from(&binding.from),
            to: SlotRefIr::from(&binding.to),
            weak: binding.weak,
        }
    }
}

impl BindingIr {
    fn into_binding(self) -> Result<BindingEdge, ScenarioIrError> {
        Ok(BindingEdge {
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
            BindingFrom::Framework(framework) => Self::Framework {
                capability: framework.capability.to_string(),
                authority_realm: framework.authority.0,
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
            BindingFromIr::Framework {
                capability,
                authority_realm,
            } => {
                let name =
                    FrameworkCapabilityName::try_from(capability.as_str()).map_err(|_| {
                        ScenarioIrError::InvalidName {
                            name: capability.clone(),
                        }
                    })?;
                Ok(BindingFrom::Framework(FrameworkRef {
                    authority: ComponentId(authority_realm),
                    capability: name,
                }))
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
    validate_mounted_storage_slots(scenario)?;
    validate_exports(scenario)?;
    validate_child_templates(scenario)?;
    Ok(())
}

fn validate_component_exports(
    component_irs: &[Option<ComponentIr>],
    components: &[Option<Component>],
) -> Result<(), ScenarioIrError> {
    for component in component_irs.iter().flatten() {
        for export_name in component.exports.keys() {
            let mut visited = Vec::new();
            validate_component_export_target(
                component_irs,
                components,
                ComponentId(component.id),
                export_name,
                &mut visited,
            )?;
        }
    }
    Ok(())
}

fn validate_component_export_target(
    component_irs: &[Option<ComponentIr>],
    components: &[Option<Component>],
    component_id: ComponentId,
    export_name: &str,
    visited: &mut Vec<(usize, String)>,
) -> Result<(), ScenarioIrError> {
    let visit_key = (component_id.0, export_name.to_string());
    if visited.contains(&visit_key) {
        return Err(invalid_scenario(format!(
            "component export cycle detected while validating component {} export `{export_name}`",
            component_id.0
        )));
    }
    visited.push(visit_key.clone());

    let result = validate_component_export_target_inner(
        component_irs,
        components,
        component_id,
        export_name,
        visited,
    );
    visited.pop();
    result
}

fn validate_component_export_target_inner(
    component_irs: &[Option<ComponentIr>],
    components: &[Option<Component>],
    component_id: ComponentId,
    export_name: &str,
    visited: &mut Vec<(usize, String)>,
) -> Result<(), ScenarioIrError> {
    let context = || {
        format!(
            "component export `{export_name}` on component {}",
            component_id.0
        )
    };
    let component_ir = component_irs
        .get(component_id.0)
        .and_then(|component| component.as_ref())
        .ok_or_else(|| invalid_scenario(context()))?;
    let target = component_ir
        .exports
        .get(export_name)
        .ok_or_else(|| invalid_scenario(context()))?;

    match target {
        ComponentExportTargetIr::SelfProvide { provide } => {
            let _ = ensure_provide(components, component_id, provide, context)?;
        }
        ComponentExportTargetIr::SelfSlot { slot } => {
            let _ = ensure_slot(components, component_id, slot, context)?;
        }
        ComponentExportTargetIr::ChildExport { child, export } => {
            let parent_moniker = component_ir.moniker.as_str();
            let child_id = component_ir
                .children
                .iter()
                .copied()
                .find(|child_id| {
                    component_irs
                        .get(*child_id)
                        .and_then(|component| component.as_ref())
                        .and_then(|component| {
                            child_alias(parent_moniker, component.moniker.as_str())
                        })
                        == Some(child.as_str())
                })
                .ok_or_else(|| {
                    invalid_scenario(format!("{} references missing child `{child}`", context()))
                })?;
            validate_component_export_target(
                component_irs,
                components,
                ComponentId(child_id),
                export,
                visited,
            )?;
        }
    }

    Ok(())
}

fn child_alias<'a>(parent_moniker: &str, child_moniker: &'a str) -> Option<&'a str> {
    if child_moniker == "/" {
        return None;
    }
    let remainder = if parent_moniker == "/" {
        child_moniker.strip_prefix('/')?
    } else {
        child_moniker
            .strip_prefix(parent_moniker)?
            .strip_prefix('/')?
    };
    remainder.split('/').find(|segment| !segment.is_empty())
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
        for name in component.child_templates.keys() {
            ensure_name_no_dot(name)?;
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

fn validate_child_templates(scenario: &Scenario) -> Result<(), ScenarioIrError> {
    for component in scenario.components.iter().flatten() {
        for (name, template) in &component.child_templates {
            match (&template.manifest, &template.allowed_manifests) {
                (Some(_), None) | (None, Some(_)) => {}
                (Some(_), Some(_)) => {
                    return Err(invalid_scenario(format!(
                        "component {} child template `{name}` specifies both `manifest` and \
                         `allowed_manifests`",
                        component.moniker.as_str()
                    )));
                }
                (None, None) => {
                    return Err(invalid_scenario(format!(
                        "component {} child template `{name}` must specify one of `manifest` or \
                         `allowed_manifests`",
                        component.moniker.as_str()
                    )));
                }
            }

            if let Some(key) = &template.manifest
                && !scenario.manifest_catalog.contains_key(key)
            {
                return Err(invalid_scenario(format!(
                    "component {} child template `{name}` references missing manifest catalog key \
                     `{key}`",
                    component.moniker.as_str()
                )));
            }

            if let Some(keys) = &template.allowed_manifests {
                if keys.is_empty() {
                    return Err(invalid_scenario(format!(
                        "component {} child template `{name}` has an empty `allowed_manifests` \
                         list",
                        component.moniker.as_str()
                    )));
                }
                for key in keys {
                    if !scenario.manifest_catalog.contains_key(key) {
                        return Err(invalid_scenario(format!(
                            "component {} child template `{name}` references missing manifest \
                             catalog key `{key}`",
                            component.moniker.as_str()
                        )));
                    }
                }
            }
        }
    }

    for (key, entry) in &scenario.manifest_catalog {
        if entry.digest != entry.manifest.digest() {
            return Err(invalid_scenario(format!(
                "manifest catalog entry `{key}` digest {} does not match manifest digest {}",
                entry.digest,
                entry.manifest.digest()
            )));
        }
    }

    Ok(())
}

fn validate_bindings(scenario: &Scenario) -> Result<(), ScenarioIrError> {
    for binding in &scenario.bindings {
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
            BindingFrom::Framework(framework) => {
                let capability = framework.capability.as_str();
                let spec = framework_capability(capability).ok_or_else(|| {
                    invalid_scenario(format!(
                        "binding into {target_label} references unknown framework capability \
                         `framework.{capability}`"
                    ))
                })?;
                (format!("framework.{capability}"), spec.decl.clone())
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

fn validate_mounted_storage_slots(scenario: &Scenario) -> Result<(), ScenarioIrError> {
    for component in scenario.components.iter().flatten() {
        let Some(program) = component.program.as_ref() else {
            continue;
        };

        for mount in program.mounts() {
            let ProgramMount::Slot { slot, .. } = mount else {
                continue;
            };
            let Some(slot_decl) = component.slots.get(slot.as_str()) else {
                continue;
            };
            if slot_decl.decl.kind != CapabilityKind::Storage {
                continue;
            }

            let bindings: Vec<_> = scenario
                .bindings
                .iter()
                .filter(|binding| binding.to.component == component.id && binding.to.name == *slot)
                .collect();
            let slot_label = format!("{}.{}", component.moniker.as_str(), slot);

            match bindings.as_slice() {
                [] => {
                    return Err(invalid_scenario(format!(
                        "mounted storage slot {slot_label} must be bound from a storage resource, \
                         but it has no binding"
                    )));
                }
                [binding] => {
                    if let BindingFrom::Resource(_) = &binding.from {
                        continue;
                    }

                    return Err(invalid_scenario(format!(
                        "mounted storage slot {slot_label} must be bound from a storage resource, \
                         but it is bound from {}",
                        describe_binding_source(scenario, &binding.from, &binding.to.name)?
                    )));
                }
                _ => {
                    return Err(invalid_scenario(format!(
                        "mounted storage slot {slot_label} must be bound from exactly one storage \
                         resource, but it has {} bindings",
                        bindings.len()
                    )));
                }
            }
        }
    }

    Ok(())
}

fn describe_binding_source(
    scenario: &Scenario,
    from: &BindingFrom,
    target_slot: &str,
) -> Result<String, ScenarioIrError> {
    match from {
        BindingFrom::Component(provide) => Ok(format!(
            "{}.{}",
            component_ref(&scenario.components, provide.component, || {
                format!("binding source for {target_slot}")
            })?
            .moniker
            .as_str(),
            provide.name
        )),
        BindingFrom::Resource(resource) => Ok(format!(
            "{}.resources.{}",
            component_ref(&scenario.components, resource.component, || {
                format!("binding source for {target_slot}")
            })?
            .moniker
            .as_str(),
            resource.name
        )),
        BindingFrom::Framework(framework) => Ok(format!("framework.{}", framework.capability)),
        BindingFrom::External(slot) => Ok(format!(
            "external {}.{}",
            component_ref(&scenario.components, slot.component, || {
                format!("binding source for {target_slot}")
            })?
            .moniker
            .as_str(),
            slot.name
        )),
    }
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

    use amber_manifest::{FrameworkCapabilityName, ManifestDigest, RuntimeBackend};
    use serde_json::json;

    use super::{
        ComponentExportTargetIr, SCENARIO_IR_SCHEMA, SCENARIO_IR_VERSION, ScenarioIr,
        ScenarioIrError,
    };
    use crate::{
        BindingEdge, BindingFrom, ChildTemplate, ChildTemplateLimits, Component, ComponentId,
        FrameworkRef, ManifestCatalogEntry, Moniker, ProvideRef, Scenario, ScenarioExport, SlotRef,
        TemplateBinding, TemplateConfigField,
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
                metadata: None,
                child_templates: BTreeMap::new(),
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
                metadata: None,
                child_templates: BTreeMap::new(),
                children: Vec::new(),
            }),
        ];

        let mut scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: vec![BindingEdge {
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
            manifest_catalog: BTreeMap::new(),
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
                            "optional": false,
                            "multiple": false
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
    fn scenario_ir_rejects_legacy_versions() {
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
        let err = Scenario::try_from(parsed).expect_err("legacy scenario IR should be rejected");
        assert!(matches!(
            err,
            ScenarioIrError::VersionMismatch {
                expected: SCENARIO_IR_VERSION,
                actual: 1
            }
        ));
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
            metadata: None,
            child_templates: BTreeMap::new(),
            children: Vec::new(),
        })];

        let mut scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: vec![BindingEdge {
                from: BindingFrom::Framework(FrameworkRef {
                    authority: ComponentId(0),
                    capability: FrameworkCapabilityName::try_from("docker").unwrap(),
                }),
                to: SlotRef {
                    component: ComponentId(0),
                    name: "docker".to_string(),
                },
                weak: false,
            }],
            exports: Vec::new(),
            manifest_catalog: BTreeMap::new(),
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
    fn scenario_ir_roundtrips_child_templates_and_manifest_catalog() {
        let catalog_manifest: amber_manifest::Manifest = r#"
            {
              manifest_version: "0.1.0",
              slots: {
                realm: { kind: "component" },
              },
            }
        "#
        .parse()
        .expect("manifest");
        let catalog_key = "file:///templates/worker.json5".to_string();

        let components = vec![Some(Component {
            id: ComponentId(0),
            parent: None,
            moniker: Moniker::from("/".to_string()),
            digest: ManifestDigest::new([0u8; 32]),
            config: None,
            config_schema: None,
            program: None,
            slots: BTreeMap::from([("realm".to_string(), slot_decl("component"))]),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            metadata: None,
            child_templates: BTreeMap::from([(
                "worker".to_string(),
                ChildTemplate {
                    manifest: Some(catalog_key.clone()),
                    allowed_manifests: None,
                    config: BTreeMap::from([(
                        "mode".to_string(),
                        TemplateConfigField::Prefilled {
                            value: json!("batch"),
                        },
                    )]),
                    bindings: BTreeMap::from([(
                        "realm".to_string(),
                        TemplateBinding::Prefilled {
                            selector: "slots.realm".parse().unwrap(),
                        },
                    )]),
                    visible_exports: Some(vec!["api".to_string()]),
                    limits: Some(ChildTemplateLimits {
                        max_live_children: Some(4),
                        name_pattern: Some("job-[0-9]+".to_string()),
                    }),
                    possible_backends: vec![RuntimeBackend::Direct],
                },
            )]),
            children: Vec::new(),
        })];

        let mut scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: Vec::new(),
            exports: Vec::new(),
            manifest_catalog: BTreeMap::from([(
                catalog_key.clone(),
                ManifestCatalogEntry {
                    source_ref: catalog_key.clone(),
                    digest: catalog_manifest.digest(),
                    manifest: catalog_manifest.clone(),
                },
            )]),
        };
        scenario.normalize_order();

        let ir = ScenarioIr::from(&scenario);
        let roundtripped: Scenario = ir.try_into().expect("deserialize scenario IR");
        assert_eq!(roundtripped, scenario);
        assert_eq!(
            roundtripped
                .component(ComponentId(0))
                .child_templates
                .get("worker")
                .and_then(|template| template.manifest.as_ref()),
            Some(&catalog_key)
        );
        assert_eq!(
            roundtripped.manifest_catalog.get(&catalog_key),
            scenario.manifest_catalog.get(&catalog_key)
        );
    }

    #[test]
    fn scenario_ir_deserializes_component_exports() {
        let ir = serde_json::from_value::<ScenarioIr>(json!({
            "schema": SCENARIO_IR_SCHEMA,
            "version": SCENARIO_IR_VERSION,
            "root": 0,
            "components": [
                {
                    "id": 0,
                    "moniker": "/",
                    "parent": null,
                    "children": [1],
                    "digest": ManifestDigest::new([0u8; 32]),
                    "config": null,
                    "program": null,
                    "slots": {},
                    "provides": {},
                    "exports": {
                        "api": {
                            "target": "child_export",
                            "child": "worker",
                            "export": "api"
                        }
                    },
                    "resources": {},
                    "child_templates": {},
                    "metadata": null
                },
                {
                    "id": 1,
                    "moniker": "/worker",
                    "parent": 0,
                    "children": [],
                    "digest": ManifestDigest::new([1u8; 32]),
                    "config": null,
                    "program": null,
                    "slots": {},
                    "provides": {
                        "api": {
                            "kind": "http"
                        }
                    },
                    "exports": {
                        "api": {
                            "target": "self_provide",
                            "provide": "api"
                        }
                    },
                    "resources": {},
                    "child_templates": {},
                    "metadata": null
                }
            ],
            "bindings": [],
            "exports": [],
            "manifest_catalog": {}
        }))
        .expect("scenario IR should decode");
        assert_eq!(
            ir.components[0].exports.get("api"),
            Some(&ComponentExportTargetIr::ChildExport {
                child: "worker".to_string(),
                export: "api".to_string(),
            })
        );
        let scenario: Scenario = ir.try_into().expect("scenario should validate");
        assert_eq!(scenario.root, ComponentId(0));
    }

    #[test]
    fn scenario_ir_validates_child_export_aliases_through_nested_child_roots() {
        let ir = serde_json::from_value::<ScenarioIr>(json!({
            "schema": SCENARIO_IR_SCHEMA,
            "version": SCENARIO_IR_VERSION,
            "root": 0,
            "components": [
                {
                    "id": 0,
                    "moniker": "/",
                    "parent": null,
                    "children": [1],
                    "digest": ManifestDigest::new([0u8; 32]),
                    "config": null,
                    "program": null,
                    "slots": {},
                    "provides": {},
                    "exports": {
                        "vm_http": {
                            "target": "child_export",
                            "child": "vm_helper",
                            "export": "http"
                        }
                    },
                    "resources": {},
                    "child_templates": {},
                    "metadata": null
                },
                {
                    "id": 1,
                    "moniker": "/vm_helper/root",
                    "parent": 0,
                    "children": [],
                    "digest": ManifestDigest::new([1u8; 32]),
                    "config": null,
                    "program": null,
                    "slots": {},
                    "provides": {
                        "http": {
                            "kind": "http"
                        }
                    },
                    "exports": {
                        "http": {
                            "target": "self_provide",
                            "provide": "http"
                        }
                    },
                    "resources": {},
                    "child_templates": {},
                    "metadata": null
                }
            ],
            "bindings": [],
            "exports": [],
            "manifest_catalog": {}
        }))
        .expect("scenario IR should decode");

        let scenario: Scenario = ir
            .try_into()
            .expect("nested child-root export should validate");
        assert_eq!(scenario.root, ComponentId(0));
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
                    "from": {
                        "kind": "framework",
                        "capability": "bad.name",
                        "authority_realm": 0
                    },
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

    #[test]
    fn scenario_ir_rejects_mounted_storage_slot_bound_from_external_slot() {
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
                        "state": { "kind": "storage" }
                    }
                },
                {
                    "id": 1,
                    "moniker": "/app",
                    "parent": 0,
                    "children": [],
                    "digest": ManifestDigest::new([1u8; 32]).to_string(),
                    "config": null,
                    "program": {
                        "image": "busybox:stable",
                        "entrypoint": ["sh"],
                        "mounts": [
                            {
                                "kind": "slot",
                                "path": "/var/lib/app",
                                "slot": "state"
                            }
                        ]
                    },
                    "slots": {
                        "state": { "kind": "storage" }
                    }
                }
            ],
            "bindings": [
                {
                    "from": { "kind": "external", "slot": { "component": 0, "slot": "state" } },
                    "to": { "component": 1, "slot": "state" },
                    "weak": true
                }
            ],
            "exports": []
        });

        let ir: ScenarioIr = serde_json::from_value(payload).expect("deserialize scenario IR");
        let err = Scenario::try_from(ir).expect_err("mounted storage should require a resource");
        let message = err.to_string();
        assert!(
            message
                .contains("mounted storage slot /app.state must be bound from a storage resource"),
            "{message}"
        );
        assert!(message.contains("external /.state"), "{message}");
    }
}
