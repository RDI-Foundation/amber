use amber_manifest::{CapabilityDecl, ManifestDigest};
use amber_scenario::{
    BindingEdge, Component, ComponentId, ProvideRef, Scenario, ScenarioExport, SlotRef,
};
use serde::Serialize;
use serde_json::Value;

use super::{Reporter, ReporterError};
use crate::CompileOutput;

const SCHEMA: &str = "amber.scenario.ir";
const VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Default)]
pub struct ScenarioIrReporter;

impl Reporter for ScenarioIrReporter {
    type Artifact = String;

    fn emit(&self, output: &CompileOutput) -> Result<Self::Artifact, ReporterError> {
        render_scenario_ir(&output.scenario)
    }
}

/// Render a Scenario graph as a stable JSON IR artifact.
pub fn render_scenario_ir(s: &Scenario) -> Result<String, ReporterError> {
    let ir = ScenarioIr::new(s);
    let mut out = serde_json::to_string_pretty(&ir)
        .map_err(|e| ReporterError::Other(format!("failed to render scenario IR: {e}")))?;
    out.push('\n');
    Ok(out)
}

#[derive(Serialize)]
struct ScenarioIr<'a> {
    schema: &'static str,
    version: u32,
    root: usize,
    components: Vec<ComponentIr<'a>>,
    bindings: Vec<BindingIr<'a>>,
    exports: Vec<ExportIr<'a>>,
}

impl<'a> ScenarioIr<'a> {
    fn new(s: &'a Scenario) -> Self {
        let components = s
            .components_iter()
            .map(|(id, component)| ComponentIr::new(id, component))
            .collect();
        let bindings = s.bindings.iter().map(BindingIr::new).collect();
        let exports = s.exports.iter().map(ExportIr::new).collect();

        Self {
            schema: SCHEMA,
            version: VERSION,
            root: s.root.0,
            components,
            bindings,
            exports,
        }
    }
}

#[derive(Serialize)]
struct ComponentIr<'a> {
    id: usize,
    moniker: &'a str,
    parent: Option<usize>,
    children: Vec<usize>,
    has_program: bool,
    digest: ManifestDigest,
    config: Option<&'a Value>,
}

impl<'a> ComponentIr<'a> {
    fn new(id: ComponentId, component: &'a Component) -> Self {
        let children = component.children.iter().map(|id| id.0).collect();

        Self {
            id: id.0,
            moniker: component.moniker.as_str(),
            parent: component.parent.map(|id| id.0),
            children,
            has_program: component.has_program,
            digest: component.digest,
            config: component.config.as_ref(),
        }
    }
}

#[derive(Serialize)]
struct BindingIr<'a> {
    from: ProvideRefIr<'a>,
    to: SlotRefIr<'a>,
    weak: bool,
}

impl<'a> BindingIr<'a> {
    fn new(binding: &'a BindingEdge) -> Self {
        Self {
            from: ProvideRefIr::new(&binding.from),
            to: SlotRefIr::new(&binding.to),
            weak: binding.weak,
        }
    }
}

#[derive(Serialize)]
struct ProvideRefIr<'a> {
    component: usize,
    provide: &'a str,
}

impl<'a> ProvideRefIr<'a> {
    fn new(provide: &'a ProvideRef) -> Self {
        Self {
            component: provide.component.0,
            provide: provide.name.as_str(),
        }
    }
}

#[derive(Serialize)]
struct SlotRefIr<'a> {
    component: usize,
    slot: &'a str,
}

impl<'a> SlotRefIr<'a> {
    fn new(slot: &'a SlotRef) -> Self {
        Self {
            component: slot.component.0,
            slot: slot.name.as_str(),
        }
    }
}

#[derive(Serialize)]
struct ExportIr<'a> {
    name: &'a str,
    capability: &'a CapabilityDecl,
    from: ProvideRefIr<'a>,
}

impl<'a> ExportIr<'a> {
    fn new(export: &'a ScenarioExport) -> Self {
        Self {
            name: export.name.as_str(),
            capability: &export.capability,
            from: ProvideRefIr::new(&export.from),
        }
    }
}
