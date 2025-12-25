#[cfg(test)]
mod tests;

use amber_manifest::ManifestRef;
use amber_resolver::Resolver;
use amber_scenario::Scenario;

mod environment;
mod frontend;
mod linker;
mod provenance;
mod store;

pub use environment::ResolverRegistry;
pub use frontend::ResolveOptions;
pub use provenance::{ComponentProvenance, Provenance};
pub use store::DigestStore;

#[derive(Clone, Debug, Default)]
pub struct CompileOptions {
    pub resolve: ResolveOptions,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Frontend(#[from] frontend::Error),
    #[error(transparent)]
    Linker(#[from] linker::Error),
}

#[derive(Clone)]
pub struct Compiler {
    resolver: Resolver,
    store: DigestStore,
    registry: ResolverRegistry,
}

impl Compiler {
    pub fn new(resolver: Resolver, store: DigestStore) -> Self {
        Self {
            resolver,
            store,
            registry: ResolverRegistry::default(),
        }
    }

    pub fn store(&self) -> &DigestStore {
        &self.store
    }

    pub fn registry(&self) -> &ResolverRegistry {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut ResolverRegistry {
        &mut self.registry
    }

    pub fn with_registry(mut self, registry: ResolverRegistry) -> Self {
        self.registry = registry;
        self
    }

    /// Compile a root manifest reference into a fully linked Scenario plus a digest store
    /// and per-component provenance.
    pub async fn compile(
        &self,
        root: ManifestRef,
        opts: CompileOptions,
    ) -> Result<Compilation, Error> {
        let tree = frontend::resolve_tree(
            self.resolver.clone(),
            self.store.clone(),
            self.registry.clone(),
            root,
            opts.resolve,
        )
        .await?;

        let (scenario, provenance) = linker::link(tree, &self.store)?;

        Ok(Compilation {
            scenario,
            store: self.store.clone(),
            provenance,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Compilation {
    pub scenario: Scenario,
    pub store: DigestStore,
    pub provenance: Provenance,
}
