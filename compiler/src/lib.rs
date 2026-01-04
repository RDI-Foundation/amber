#[cfg(test)]
mod tests;

use amber_manifest::{ManifestRef, lint::lint_manifest};
use amber_resolver::Resolver;
use amber_scenario::Scenario;
use miette::{Diagnostic, Report};
use thiserror::Error;

mod environment;
mod frontend;
mod linker;
mod manifest_table;
mod provenance;
mod store;

pub mod passes;
pub mod reporter;

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

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    #[diagnostic(transparent)]
    Frontend(#[from] frontend::Error),

    #[error(transparent)]
    #[diagnostic(transparent)]
    Linker(#[from] linker::Error),

    #[error(transparent)]
    #[diagnostic(transparent)]
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
        let diagnostics = collect_manifest_diagnostics(&scenario, &provenance, &self.store);

        let (scenario, provenance) = {
            let mut pm = passes::PassManager::new();
            if opts.optimize.dce {
                pm.push(passes::DcePass);
                pm.push(passes::FlattenPass);
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

    /// Resolve and lint manifests, then attempt to link and report as many errors as possible.
    pub async fn check(
        &self,
        root: ManifestRef,
        opts: CompileOptions,
    ) -> Result<CheckOutput, Error> {
        let tree = frontend::resolve_tree(
            self.resolver.clone(),
            self.store.clone(),
            self.registry.clone(),
            root,
            opts.resolve,
        )
        .await?;

        let mut diagnostics = collect_manifest_diagnostics_from_tree(&tree, &self.store);
        let mut has_errors = false;

        match linker::link(tree, &self.store) {
            Ok((_scenario, _provenance)) => {}
            Err(err) => {
                has_errors = true;
                let mut link_errors = Vec::new();
                match err {
                    linker::Error::Multiple { errors, .. } => link_errors.extend(errors),
                    other => link_errors.push(other),
                }
                diagnostics.extend(link_errors.into_iter().map(Report::new));
            }
        }

        Ok(CheckOutput {
            diagnostics,
            has_errors,
        })
    }
}

#[derive(Debug)]
pub struct CompileOutput {
    pub scenario: Scenario,
    pub store: DigestStore,
    pub provenance: Provenance,
    pub diagnostics: Vec<Report>,
}

#[derive(Debug)]
pub struct CheckOutput {
    pub diagnostics: Vec<Report>,
    pub has_errors: bool,
}

fn collect_manifest_diagnostics(
    scenario: &Scenario,
    provenance: &Provenance,
    store: &DigestStore,
) -> Vec<Report> {
    let mut diagnostics = Vec::new();

    for (_, component) in scenario.components_iter() {
        let manifest = store
            .get(&component.digest)
            .expect("manifest was resolved during linking");
        let prov = provenance.for_component(component.id);
        let url = prov.effective_url();
        let component_path = prov.authored_moniker.as_str();

        let Some((src, spans)) = store.diagnostic_source(url) else {
            continue;
        };
        let lints = lint_manifest(&manifest, component_path, src, spans.as_ref());
        if lints.is_empty() {
            continue;
        }

        diagnostics.extend(lints.into_iter().map(Report::new));
    }

    diagnostics
}

fn collect_manifest_diagnostics_from_tree(
    tree: &frontend::ResolvedTree,
    store: &DigestStore,
) -> Vec<Report> {
    let mut diagnostics = Vec::new();
    collect_tree_node_diagnostics(&tree.root, "/", store, &mut diagnostics);
    diagnostics
}

fn collect_tree_node_diagnostics(
    node: &frontend::ResolvedNode,
    component_path: &str,
    store: &DigestStore,
    diagnostics: &mut Vec<Report>,
) {
    let Some(manifest) = store.get(&node.digest) else {
        return;
    };

    let url = node.observed_url.as_ref().unwrap_or(&node.resolved_url);
    let Some((src, spans)) = store.diagnostic_source(url) else {
        return;
    };
    let lints = lint_manifest(manifest.as_ref(), component_path, src, spans.as_ref());
    diagnostics.extend(lints.into_iter().map(Report::new));

    for (child_name, child_node) in &node.children {
        let child_path = if component_path == "/" {
            format!("/{child_name}")
        } else {
            format!("{component_path}/{child_name}")
        };
        collect_tree_node_diagnostics(child_node, &child_path, store, diagnostics);
    }
}
