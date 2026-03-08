use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[cfg(test)]
mod tests;

use amber_manifest::{
    ExperimentalFeature, Manifest, ManifestRef,
    lint::{ManifestLint, lint_manifest},
};
use amber_resolver::Resolver;
use amber_scenario::{ComponentId, Scenario};
use miette::{Diagnostic, Report};
use thiserror::Error;

mod binding_query;
mod binding_usage;
mod binding_validation;
pub(crate) mod config_scope;
mod config_template;
mod config_templates;
mod environment;
mod frontend;
mod linker;
mod manifest_table;
pub mod mesh;
mod mir;
mod provenance;
mod slot_query;
mod slot_validation;
mod storage_plan;
mod store;
mod targets;

pub mod bundle;
pub mod reporter;

pub use environment::ResolverRegistry;
pub use frontend::{ResolveOptions, ResolvedNode, ResolvedTree};
pub use provenance::{ComponentProvenance, Provenance};
pub use store::DigestStore;

#[derive(Clone, Debug, Default)]
pub struct CompileOptions {
    pub resolve: ResolveOptions,
    pub optimize: OptimizeOptions,
}

impl CompileOptions {
    #[cfg(test)]
    pub(crate) fn testing(dce: bool) -> Self {
        Self {
            resolve: ResolveOptions { max_concurrency: 8 },
            optimize: OptimizeOptions { dce },
        }
    }
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
    Mir(#[from] mir::Error),
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

    pub async fn resolve_tree(
        &self,
        root: ManifestRef,
        opts: ResolveOptions,
    ) -> Result<ResolvedTree, Error> {
        Ok(frontend::resolve_tree(
            self.resolver.clone(),
            self.store.clone(),
            self.registry.clone(),
            root,
            opts,
        )
        .await?)
    }

    #[allow(clippy::result_large_err)]
    pub fn compile_from_tree(
        &self,
        tree: ResolvedTree,
        opts: OptimizeOptions,
    ) -> Result<CompileOutput, Error> {
        let mut diagnostics =
            slot_validation::collect_slot_interpolation_diagnostics_from_tree(&tree, &self.store);
        let binding_validation::BindingInterpolationDiagnostics {
            diagnostics: binding_reports,
            suppressed_unused_config_lints,
        } = binding_validation::collect_binding_interpolation_diagnostics_from_tree(
            &tree,
            &self.store,
        );
        diagnostics.extend(binding_reports);
        let (scenario, provenance) = linker::link(tree, &self.store)?;
        diagnostics.extend(collect_manifest_diagnostics(
            &scenario,
            &provenance,
            &self.store,
            &suppressed_unused_config_lints,
        ));

        let (scenario, provenance) = mir::optimize_linked_scenario(
            scenario,
            provenance,
            &self.store,
            mir::OptimizeOptions { dce: opts.dce },
        )?;

        Ok(CompileOutput {
            scenario,
            store: self.store.clone(),
            provenance,
            diagnostics,
        })
    }

    #[allow(clippy::result_large_err)]
    pub fn check_from_tree(&self, tree: ResolvedTree) -> Result<CheckOutput, Error> {
        let mut diagnostics =
            slot_validation::collect_slot_interpolation_diagnostics_from_tree(&tree, &self.store);
        let binding_validation::BindingInterpolationDiagnostics {
            diagnostics: binding_reports,
            suppressed_unused_config_lints,
        } = binding_validation::collect_binding_interpolation_diagnostics_from_tree(
            &tree,
            &self.store,
        );
        diagnostics.extend(binding_reports);
        let mut has_errors = false;
        let tree_for_manifest_lints = tree.clone();

        match linker::link(tree, &self.store) {
            Ok((scenario, provenance)) => diagnostics.extend(collect_manifest_diagnostics(
                &scenario,
                &provenance,
                &self.store,
                &suppressed_unused_config_lints,
            )),
            Err(err) => {
                has_errors = true;
                diagnostics.extend(collect_manifest_diagnostics_from_tree(
                    &tree_for_manifest_lints,
                    &self.store,
                    &suppressed_unused_config_lints,
                ));
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

    /// Compile a root manifest reference into a fully linked Scenario plus a digest store,
    /// per-component provenance, and diagnostics.
    pub async fn compile(
        &self,
        root: ManifestRef,
        opts: CompileOptions,
    ) -> Result<CompileOutput, Error> {
        let tree = self.resolve_tree(root, opts.resolve).await?;
        self.compile_from_tree(tree, opts.optimize)
    }

    /// Resolve and lint manifests, then attempt to link and report as many errors as possible.
    pub async fn check(
        &self,
        root: ManifestRef,
        opts: CompileOptions,
    ) -> Result<CheckOutput, Error> {
        let tree = self.resolve_tree(root, opts.resolve).await?;
        self.check_from_tree(tree)
    }
}

#[derive(Debug)]
pub struct CompileOutput {
    pub scenario: Scenario,
    pub store: DigestStore,
    pub provenance: Provenance,
    pub diagnostics: Vec<Report>,
}

impl CompileOutput {
    pub fn manifest_for_component(&self, id: ComponentId) -> Option<Arc<Manifest>> {
        let component = self.scenario.components.get(id.0)?.as_ref()?;
        self.store.get(&component.digest)
    }

    pub fn component_declares_experimental_feature(
        &self,
        id: ComponentId,
        feature: ExperimentalFeature,
    ) -> bool {
        self.manifest_for_component(id)
            .is_some_and(|manifest| manifest.uses_experimental_feature(feature))
    }
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
    suppressed_unused_config_lints: &binding_validation::SuppressedUnusedConfigLints,
) -> Vec<Report> {
    let mut diagnostics = Vec::new();
    let optional_slots = effective_optional_slots_by_component(scenario, provenance);

    for (_, component) in scenario.components_iter() {
        let manifest = store
            .get(&component.digest)
            .expect("manifest was resolved during linking");
        let prov = provenance.for_component(component.id);
        let url = &prov.resolved_url;
        let component_path = prov.authored_moniker.as_str();

        let Some((src, spans)) = store.diagnostic_source(url) else {
            continue;
        };
        let lints = lint_manifest(&manifest, component_path, src, spans.as_ref());
        if lints.is_empty() {
            continue;
        }

        diagnostics.extend(
            lints
                .into_iter()
                .filter(|lint| {
                    !suppress_manifest_unused_config_lint(lint, suppressed_unused_config_lints)
                        && !suppress_manifest_unused_slot_lint(lint, &optional_slots)
                })
                .map(Report::new),
        );
    }

    diagnostics
}

fn collect_manifest_diagnostics_from_tree(
    tree: &frontend::ResolvedTree,
    store: &DigestStore,
    suppressed_unused_config_lints: &binding_validation::SuppressedUnusedConfigLints,
) -> Vec<Report> {
    let mut diagnostics = Vec::new();
    collect_tree_node_diagnostics(
        &tree.root,
        "/",
        store,
        &mut diagnostics,
        suppressed_unused_config_lints,
    );
    diagnostics
}

fn collect_tree_node_diagnostics(
    node: &frontend::ResolvedNode,
    component_path: &str,
    store: &DigestStore,
    diagnostics: &mut Vec<Report>,
    suppressed_unused_config_lints: &binding_validation::SuppressedUnusedConfigLints,
) {
    let Some(manifest) = store.get(&node.digest) else {
        return;
    };

    let url = &node.resolved_url;
    let Some((src, spans)) = store.diagnostic_source(url) else {
        return;
    };
    let lints = lint_manifest(manifest.as_ref(), component_path, src, spans.as_ref());
    diagnostics.extend(
        lints
            .into_iter()
            .filter(|lint| {
                !suppress_manifest_unused_config_lint(lint, suppressed_unused_config_lints)
            })
            .map(Report::new),
    );

    for (child_name, child_node) in &node.children {
        let child_path = if component_path == "/" {
            format!("/{child_name}")
        } else {
            format!("{component_path}/{child_name}")
        };
        collect_tree_node_diagnostics(
            child_node,
            &child_path,
            store,
            diagnostics,
            suppressed_unused_config_lints,
        );
    }
}

fn suppress_manifest_unused_config_lint(
    lint: &ManifestLint,
    suppressed_unused_config_lints: &binding_validation::SuppressedUnusedConfigLints,
) -> bool {
    let ManifestLint::UnusedConfig {
        path, component, ..
    } = lint
    else {
        return false;
    };
    suppressed_unused_config_lints
        .get(component)
        .is_some_and(|paths| paths.contains(path))
}

fn suppress_manifest_unused_slot_lint(
    lint: &ManifestLint,
    optional_slots_by_component: &BTreeMap<String, BTreeSet<String>>,
) -> bool {
    let ManifestLint::UnusedSlot {
        name, component, ..
    } = lint
    else {
        return false;
    };

    optional_slots_by_component
        .get(component)
        .is_some_and(|slots| slots.contains(name))
}

fn effective_optional_slots_by_component(
    scenario: &Scenario,
    provenance: &Provenance,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut out = BTreeMap::new();

    for (_, component) in scenario.components_iter() {
        let component_path = provenance
            .for_component(component.id)
            .authored_moniker
            .to_string();
        let slots = out.entry(component_path).or_insert_with(BTreeSet::new);
        for (slot_name, slot_decl) in &component.slots {
            if slot_decl.optional {
                slots.insert(slot_name.clone());
            }
        }
    }

    for binding in &scenario.bindings {
        if !binding.weak {
            continue;
        }
        let component_path = provenance
            .for_component(binding.to.component)
            .authored_moniker
            .to_string();
        out.entry(component_path)
            .or_insert_with(BTreeSet::new)
            .insert(binding.to.name.clone());
    }

    out
}
