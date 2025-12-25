use amber_manifest::{ManifestDigest, ManifestRef};
use amber_scenario::ComponentId;
use url::Url;

/// Per-compilation provenance captured alongside the Scenario graph.
#[derive(Clone, Debug, Default)]
pub struct Provenance {
    pub components: Vec<ComponentProvenance>,
}

impl Provenance {
    pub fn for_component(&self, id: ComponentId) -> &ComponentProvenance {
        &self.components[id.0]
    }
}

#[derive(Clone, Debug)]
pub struct ComponentProvenance {
    /// What was declared by the parent (URL + optional digest pin).
    pub declared_ref: ManifestRef,
    /// Digest chosen for this component instance.
    pub digest: ManifestDigest,
    /// Optional diagnostic only: where bytes were observed to come from (e.g. final URL after redirects).
    pub observed_url: Option<Url>,
}
