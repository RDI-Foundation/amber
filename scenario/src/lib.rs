use std::{collections::BTreeMap, sync::Arc};

use amber_manifest::{Manifest, ManifestDigest, ManifestRef};
use serde_json::Value;
use url::Url;

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

    /// What was declared by the parent.
    pub declared_ref: ManifestRef,

    /// Where the manifest content was actually resolved from.
    pub resolved_url: Url,

    /// Digest of the resolved manifest (using the compiler's chosen algorithm).
    pub digest: ManifestDigest,

    /// The resolved manifest contents.
    pub manifest: Arc<Manifest>,

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
