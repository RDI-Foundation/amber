use amber_scenario::{BindingEdge, Component, ComponentId, Scenario};
use miette::Diagnostic;
use thiserror::Error;

use crate::{DigestStore, Provenance};

pub mod dce;
pub mod flatten;

pub use dce::DcePass;
pub use flatten::FlattenPass;

fn prune_and_rebuild_scenario(
    scenario: Scenario,
    removed: &[bool],
    mut update_component: impl FnMut(ComponentId, &mut Component),
    mut keep_binding: impl FnMut(usize, &BindingEdge) -> bool,
) -> Scenario {
    let Scenario {
        root,
        mut components,
        bindings,
        exports,
    } = scenario;

    debug_assert_eq!(removed.len(), components.len());
    debug_assert!(!removed[root.0], "root must not be removed");
    debug_assert!(components[root.0].is_some(), "root component should exist");
    debug_assert!(
        exports
            .iter()
            .all(|export| !removed[export.from.component.0]),
        "scenario export target must not be removed"
    );

    for (idx, component) in components.iter_mut().enumerate() {
        if removed[idx] {
            *component = None;
            continue;
        }

        let id = ComponentId(idx);
        let component = component.as_mut().expect("kept component should exist");
        update_component(id, component);
        component.children.clear();
    }

    let mut edges = Vec::new();
    for (idx, component) in components.iter().enumerate() {
        let Some(component) = component.as_ref() else {
            continue;
        };
        let Some(parent) = component.parent else {
            continue;
        };
        if removed[parent.0] {
            continue;
        }
        edges.push((parent, ComponentId(idx)));
    }
    for (parent, child) in edges {
        let parent_component = components[parent.0].as_mut().expect("parent should exist");
        parent_component.children.push(child);
    }

    let mut new_bindings = Vec::with_capacity(bindings.len());
    for (idx, binding) in bindings.into_iter().enumerate() {
        if !keep_binding(idx, &binding) {
            continue;
        }
        if removed[binding.from.component.0] || removed[binding.to.component.0] {
            continue;
        }
        new_bindings.push(binding);
    }

    let mut scenario = Scenario {
        root,
        components,
        bindings: new_bindings,
        exports,
    };
    scenario.normalize_order();
    scenario
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum PassError {
    #[error("pass `{pass}` failed: {message}")]
    #[diagnostic(code(compiler::pass_failed))]
    Failed { pass: &'static str, message: String },
}

pub trait ScenarioPass {
    fn name(&self) -> &'static str;

    fn run(
        &self,
        scenario: Scenario,
        provenance: Provenance,
        store: &DigestStore,
    ) -> Result<(Scenario, Provenance), PassError>;
}

#[derive(Default)]
pub struct PassManager {
    passes: Vec<Box<dyn ScenarioPass>>,
}

impl PassManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push<P>(&mut self, pass: P)
    where
        P: ScenarioPass + 'static,
    {
        self.passes.push(Box::new(pass));
    }

    pub fn run(
        &self,
        mut scenario: Scenario,
        mut provenance: Provenance,
        store: &DigestStore,
    ) -> Result<(Scenario, Provenance), PassError> {
        for pass in &self.passes {
            (scenario, provenance) = pass.run(scenario, provenance, store)?;
        }
        Ok((scenario, provenance))
    }
}
