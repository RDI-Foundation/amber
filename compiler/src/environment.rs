use std::{collections::HashMap, sync::Arc};

use amber_resolver::RemoteResolver;

/// Registry of host-provided resolvers that manifests can reference by name in `environments.*.resolvers`.
///
/// This deliberately keeps the manifest declarative and prevents untrusted manifests from
/// instantiating arbitrary resolver backends.
///
/// Implementation notes:
/// - Cheap to clone (Arc).
/// - Mutations use Arc::make_mut so you can build it ergonomically and still share it.
#[derive(Clone, Debug, Default)]
pub struct ResolverRegistry {
    inner: Arc<HashMap<Arc<str>, RemoteResolver>>,
}

impl ResolverRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: impl Into<Arc<str>>, resolver: RemoteResolver) {
        Arc::make_mut(&mut self.inner).insert(name.into(), resolver);
    }

    pub fn get(&self, name: &str) -> Option<RemoteResolver> {
        self.inner.get(name).cloned()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.inner.contains_key(name)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}
