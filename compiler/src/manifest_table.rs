use std::sync::Arc;

use amber_manifest::Manifest;
use amber_scenario::{Component, ComponentId};

use crate::DigestStore;

#[derive(Clone, Copy, Debug)]
pub struct MissingManifest {
    pub component: ComponentId,
    pub digest: amber_manifest::ManifestDigest,
}

pub fn build_manifest_table(
    components: &[Option<Component>],
    store: &DigestStore,
) -> Result<Vec<Option<Arc<Manifest>>>, MissingManifest> {
    let mut out = Vec::with_capacity(components.len());
    for (idx, c) in components.iter().enumerate() {
        let Some(c) = c.as_ref() else {
            out.push(None);
            continue;
        };
        let Some(m) = store.get(&c.digest) else {
            return Err(MissingManifest {
                component: ComponentId(idx),
                digest: c.digest,
            });
        };
        out.push(Some(m));
    }
    Ok(out)
}
