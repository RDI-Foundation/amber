use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use amber_manifest::{
    CapabilityDecl, FrameworkCapabilityName, ManifestDigest, Program, ProvideDecl, SlotDecl,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod graph;
pub mod ir;

pub use ir::{SCENARIO_IR_SCHEMA, SCENARIO_IR_VERSION, ScenarioIr, ScenarioIrError};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ComponentId(pub usize);

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub struct Moniker(Arc<str>);

impl Moniker {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn local_name(&self) -> Option<&str> {
        let s = self.as_str();
        if s == "/" {
            return None;
        }
        s.rsplit('/').find(|seg| !seg.is_empty())
    }
}

impl From<Arc<str>> for Moniker {
    fn from(value: Arc<str>) -> Self {
        Self(value)
    }
}

impl From<String> for Moniker {
    fn from(value: String) -> Self {
        Self(Arc::from(value))
    }
}

impl From<Moniker> for String {
    fn from(value: Moniker) -> Self {
        value.0.to_string()
    }
}

impl std::fmt::Display for Moniker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for Moniker {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Clone, Debug)]
pub struct Scenario {
    pub root: ComponentId,
    pub components: Vec<Option<Component>>,
    pub bindings: Vec<BindingEdge>,
    pub exports: Vec<ScenarioExport>,
}

impl Scenario {
    pub fn component(&self, id: ComponentId) -> &Component {
        self.components[id.0]
            .as_ref()
            .expect("component should exist")
    }

    pub fn component_mut(&mut self, id: ComponentId) -> &mut Component {
        self.components[id.0]
            .as_mut()
            .expect("component should exist")
    }

    pub fn components_iter(&self) -> impl Iterator<Item = (ComponentId, &Component)> {
        self.components
            .iter()
            .enumerate()
            .filter_map(|(idx, component)| component.as_ref().map(|c| (ComponentId(idx), c)))
    }

    pub fn components_iter_mut(&mut self) -> impl Iterator<Item = (ComponentId, &mut Component)> {
        self.components
            .iter_mut()
            .enumerate()
            .filter_map(|(idx, component)| component.as_mut().map(|c| (ComponentId(idx), c)))
    }

    pub fn normalize_export_order_by_name(&mut self) {
        self.exports.sort_by(|a, b| a.name.cmp(&b.name));
    }

    pub fn normalize_child_order_by_moniker(&mut self) {
        let monikers: Vec<Option<Moniker>> = self
            .components
            .iter()
            .map(|c| c.as_ref().map(|c| c.moniker.clone()))
            .collect();

        for component in self.components.iter_mut().flatten() {
            component.children.sort_by(|a, b| {
                let left = monikers[a.0]
                    .as_ref()
                    .expect("child component should exist");
                let right = monikers[b.0]
                    .as_ref()
                    .expect("child component should exist");
                left.cmp(right)
            });
        }
    }

    pub fn normalize_order(&mut self) {
        self.normalize_child_order_by_moniker();
        self.normalize_export_order_by_name();
    }

    /// Debug-only validation for post-link invariants.
    pub fn assert_invariants(&self) {
        if !cfg!(debug_assertions) {
            return;
        }

        let _ = self.component(self.root);

        for (id, component) in self.components_iter() {
            if let Some(parent) = component.parent {
                let parent_component = self.component(parent);
                debug_assert!(
                    parent_component.children.contains(&id),
                    "parent missing child edge"
                );
            }

            let mut seen = HashSet::new();
            let mut last_moniker: Option<&Moniker> = None;
            for &child in &component.children {
                debug_assert!(seen.insert(child), "duplicate child edge");
                let child_component = self.component(child);
                debug_assert_eq!(
                    child_component.parent,
                    Some(id),
                    "child parent pointer mismatch"
                );
                if let Some(prev) = last_moniker {
                    debug_assert!(
                        prev <= &child_component.moniker,
                        "children not ordered by moniker"
                    );
                }
                last_moniker = Some(&child_component.moniker);
            }
        }

        for binding in &self.bindings {
            if let BindingFrom::Component(provide) = &binding.from {
                let _ = self.component(provide.component);
            }
            let _ = self.component(binding.to.component);
        }

        let mut export_names = HashSet::new();
        for export in &self.exports {
            debug_assert!(
                export_names.insert(&export.name),
                "duplicate scenario export name"
            );
            let _ = self.component(export.from.component);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Component {
    pub id: ComponentId,
    pub parent: Option<ComponentId>,
    pub moniker: Moniker,

    /// Digest of the resolved manifest (compiler-chosen algorithm).
    pub digest: ManifestDigest,

    /// Optional instance config (authored at the use-site).
    pub config: Option<Value>,

    /// Program definition (image/entrypoint/env/network) extracted from the manifest.
    pub program: Option<Program>,

    /// Declared input slots (capability requirements).
    pub slots: BTreeMap<String, SlotDecl>,

    /// Declared output provides (capability outputs).
    pub provides: BTreeMap<String, ProvideDecl>,

    /// Containment edges (component tree).
    pub children: Vec<ComponentId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProvideRef {
    pub component: ComponentId,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BindingFrom {
    Component(ProvideRef),
    Framework(FrameworkCapabilityName),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SlotRef {
    pub component: ComponentId,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct BindingEdge {
    /// Optional binding name as authored in the manifest.
    pub name: Option<String>,
    pub from: BindingFrom,
    pub to: SlotRef,
    /// If true, this edge does not participate in dependency ordering or cycle detection.
    pub weak: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ScenarioExport {
    pub name: String,
    pub capability: CapabilityDecl,
    pub from: ProvideRef,
}
