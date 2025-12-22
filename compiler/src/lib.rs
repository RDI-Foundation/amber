#[cfg(test)]
mod tests;

use amber_manifest::ManifestRef;
use amber_resolver::{Cache, Resolver};
use amber_scenario::Scenario;

mod environment;
mod frontend;
mod linker;

pub use environment::ResolverRegistry;
pub use frontend::{ResolveMode, ResolveOptions};

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
    cache: Cache,
    registry: ResolverRegistry,
}

impl Compiler {
    pub fn new(resolver: Resolver, cache: Cache) -> Self {
        Self {
            resolver,
            cache,
            registry: ResolverRegistry::default(),
        }
    }

    pub fn cache(&self) -> &Cache {
        &self.cache
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

    /// Compile a root manifest reference into a fully linked Scenario.
    pub async fn compile(
        &self,
        root: ManifestRef,
        opts: CompileOptions,
    ) -> Result<Scenario, Error> {
        let tree = frontend::resolve_tree(
            self.resolver.clone(),
            self.cache.clone(),
            self.registry.clone(),
            root,
            opts.resolve,
        )
        .await?;

        Ok(linker::link(tree)?)
    }
}
