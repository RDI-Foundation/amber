use std::collections::BTreeMap;

use amber_manifest::ManifestDigest;
use serde_json::Value;

pub mod graph;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ComponentId(pub usize);

#[derive(Clone, Debug)]
pub struct Scenario {
    pub root: ComponentId,
    pub components: Vec<Component>,
    pub bindings: Vec<BindingEdge>,
}

#[derive(Clone, Debug)]
pub struct Component {
    pub id: ComponentId,
    pub parent: Option<ComponentId>,
    pub name: String,

    /// Digest of the resolved manifest (compiler-chosen algorithm).
    pub digest: ManifestDigest,

    /// Optional instance config (authored at the use-site).
    pub config: Option<Value>,

    /// Containment edges (component tree).
    pub children: BTreeMap<String, ComponentId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ProvideRef {
    pub component: ComponentId,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SlotRef {
    pub component: ComponentId,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct BindingEdge {
    pub from: ProvideRef,
    pub to: SlotRef,
    /// If true, this edge does not participate in dependency ordering or cycle detection.
    pub weak: bool,
}
