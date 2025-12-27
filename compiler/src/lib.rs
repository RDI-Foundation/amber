#[cfg(test)]
mod tests;

use amber_manifest::{ManifestRef, lint::lint_manifest};
use amber_resolver::Resolver;
use amber_scenario::{Scenario, graph::component_path_for};

mod environment;
mod frontend;
mod linker;
mod provenance;
mod store;

pub mod backend;
pub mod passes;

pub use environment::ResolverRegistry;
pub use frontend::ResolveOptions;
pub use provenance::{ComponentProvenance, Provenance};
pub use store::DigestStore;

#[derive(Clone, Debug, Default)]
pub struct CompileOptions {
    pub resolve: ResolveOptions,
    pub optimize: OptimizeOptions,
}

#[derive(Clone, Debug)]
pub struct OptimizeOptions {
    pub dce: bool,
}

impl Default for OptimizeOptions {
    fn default() -> Self {
        Self { dce: true }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticLevel {
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub level: DiagnosticLevel,
    pub code: &'static str,
    pub message: String,
    pub component_path: String,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Frontend(#[from] frontend::Error),
    #[error(transparent)]
    Linker(#[from] linker::Error),
    #[error(transparent)]
    Pass(#[from] passes::PassError),
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

    /// Compile a root manifest reference into a fully linked Scenario plus a digest store,
    /// per-component provenance, and diagnostics.
    pub async fn compile(
        &self,
        root: ManifestRef,
        opts: CompileOptions,
    ) -> Result<CompileOutput, Error> {
        let tree = frontend::resolve_tree(
            self.resolver.clone(),
            self.store.clone(),
            self.registry.clone(),
            root,
            opts.resolve,
        )
        .await?;

        let (scenario, provenance) = linker::link(tree, &self.store)?;
        let diagnostics = collect_manifest_diagnostics(&scenario, &self.store);

        let (scenario, provenance) = {
            let mut pm = passes::PassManager::new();
            if opts.optimize.dce {
                pm.push(passes::DcePass);
            }
            pm.run(scenario, provenance, &self.store)?
        };

        Ok(CompileOutput {
            scenario,
            store: self.store.clone(),
            provenance,
            diagnostics,
        })
    }
}

#[derive(Clone, Debug)]
pub struct CompileOutput {
    pub scenario: Scenario,
    pub store: DigestStore,
    pub provenance: Provenance,
    pub diagnostics: Vec<Diagnostic>,
}

fn collect_manifest_diagnostics(scenario: &Scenario, store: &DigestStore) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    for component in &scenario.components {
        let manifest = store
            .get(&component.digest)
            .expect("manifest was resolved during linking");
        let lints = lint_manifest(&manifest);
        if lints.is_empty() {
            continue;
        }

        let component_path = component_path_for(&scenario.components, component.id);
        for lint in lints {
            diagnostics.push(Diagnostic {
                level: DiagnosticLevel::Warning,
                code: lint.code().as_str(),
                message: lint.to_string(),
                component_path: component_path.clone(),
            });
        }
    }

    diagnostics
}
