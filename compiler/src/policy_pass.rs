use std::collections::{BTreeMap, BTreeSet, HashSet};

use amber_manifest::{CapabilityDecl, ExperimentalFeature, ExportName};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, Scenario,
    ScenarioExport, ScenarioIr, ScenarioIrError, SlotRef,
};
use futures::future;
use miette::Diagnostic;
use thiserror::Error;

use crate::{
    Governance, GovernedScope,
    governance_runtime::{GovernanceRuntime, GovernanceRuntimeError},
    policy::{
        AttachmentId, PolicyInput, PolicyOutput, PolicyRequest, ScenarioScope, ScopeBinding,
        ScopeBindingFrom, ScopeExport, ScopeImport, ValidationError, validate_policy_output,
    },
    reporter::{CompiledScenario, CompiledScenarioError},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyApplication {
    pub scope_root: Moniker,
    pub scope_depth: usize,
    pub policy_index: usize,
    pub input: PolicyInput,
    targets: BTreeMap<AttachmentId, TargetDescriptor>,
    pub output: PolicyOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum TargetKey {
    Binding(usize),
    Export(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum AttachmentSide {
    Source,
    Common,
    Target,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TargetDescriptor {
    key: TargetKey,
    side: AttachmentSide,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingAttachment {
    scope_root: Moniker,
    scope_depth: usize,
    policy_index: usize,
    side: AttachmentSide,
    component: ComponentId,
    interposer_slot: String,
    interposer_provide: String,
}

struct ScopeArtifacts {
    input: PolicyInput,
    targets: BTreeMap<AttachmentId, TargetDescriptor>,
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum Error {
    #[error(
        "binding target `{component}.{slot}` is missing while building policy input for scope \
         `{root_moniker}`"
    )]
    #[diagnostic(code(compiler::policy_pass_missing_target_slot))]
    MissingTargetSlot {
        root_moniker: Moniker,
        component: Moniker,
        slot: String,
    },

    #[error(
        "governance policies require a runtime, but none was configured while compiling scope \
         `{scope_root}`"
    )]
    #[diagnostic(code(compiler::policy_pass_missing_governance_runtime))]
    MissingGovernanceRuntime { scope_root: Moniker },

    #[error("failed to start governance artifact")]
    #[diagnostic(code(compiler::policy_pass_start_governance))]
    StartGovernance {
        #[source]
        source: GovernanceRuntimeError,
    },

    #[error("failed to compile governance artifact")]
    #[diagnostic(code(compiler::policy_pass_compile_governance))]
    CompileGovernance {
        #[source]
        source: CompiledScenarioError,
    },

    #[error("failed to stop governance artifact")]
    #[diagnostic(code(compiler::policy_pass_stop_governance))]
    StopGovernance {
        #[source]
        source: GovernanceRuntimeError,
    },

    #[error("policy `{policy}` in scope `{scope_root}` failed")]
    #[diagnostic(code(compiler::policy_pass_invoke_policy))]
    InvokePolicy {
        scope_root: Moniker,
        policy: ExportName,
        #[source]
        source: GovernanceRuntimeError,
    },

    #[error("policy `{policy}` in scope `{scope_root}` returned invalid output")]
    #[diagnostic(code(compiler::policy_pass_invalid_output))]
    InvalidPolicyOutput {
        scope_root: Moniker,
        policy: ExportName,
        #[source]
        source: Box<ValidationError>,
    },

    #[error("attachment target {target} is missing while rewriting scope `{scope_root}`")]
    #[diagnostic(code(compiler::policy_pass_missing_attachment_target))]
    MissingAttachmentTarget {
        scope_root: Moniker,
        target: AttachmentId,
    },

    #[error(transparent)]
    #[diagnostic(code(compiler::policy_pass_invalid_rewritten_scenario))]
    InvalidRewrittenScenario(#[from] ScenarioIrError),
}

pub(crate) async fn apply_policies(
    scenario: Scenario,
    governance: Option<&Governance>,
    runtime: Option<&dyn GovernanceRuntime>,
) -> Result<Scenario, Error> {
    let Some(governance) = governance else {
        return Ok(scenario);
    };
    if governance.scopes.is_empty() {
        return Ok(scenario);
    }
    let Some(runtime) = runtime else {
        return Err(Error::MissingGovernanceRuntime {
            scope_root: governance.scopes[0].root_moniker.clone(),
        });
    };

    let collected = collect_policy_outputs(&scenario, governance, runtime).await?;
    rewrite_scenario(scenario, &collected)
}

async fn collect_policy_outputs(
    scenario: &Scenario,
    governance: &Governance,
    runtime: &dyn GovernanceRuntime,
) -> Result<Vec<PolicyApplication>, Error> {
    let compiled = CompiledScenario::from_scenario_with_provenance(
        &governance.scenario,
        &governance.provenance,
    )
    .map_err(|source| Error::CompileGovernance { source })?;
    let session = runtime
        .start(&compiled)
        .await
        .map_err(|source| Error::StartGovernance { source })?;
    let session_ref = session.as_ref();
    let collected = async {
        let mut invocations = Vec::new();

        for scope in &governance.scopes {
            let ScopeArtifacts { input, targets } = build_scope_artifacts(scenario, scope)?;
            let scope_depth_value = scope_depth(&scope.root_moniker);

            for (policy_index, policy) in scope.policies.iter().enumerate() {
                let scope_root = scope.root_moniker.clone();
                let policy_index_value = policy_index;
                let policy_export = policy.export.clone();
                let request = PolicyRequest {
                    scope: input.clone(),
                };
                let input = input.clone();
                let targets = targets.clone();

                invocations.push(async move {
                    let output = session_ref
                        .invoke_policy(&policy_export, &request)
                        .await
                        .map_err(|source| Error::InvokePolicy {
                            scope_root: scope_root.clone(),
                            policy: policy_export.clone(),
                            source,
                        })?;
                    // Generated interposers may not rely on experimental features.
                    validate_policy_output(
                        &output,
                        &input,
                        &BTreeSet::<ExperimentalFeature>::new(),
                    )
                    .map_err(|source| Error::InvalidPolicyOutput {
                        scope_root: scope_root.clone(),
                        policy: policy_export.clone(),
                        source: Box::new(source),
                    })?;
                    Ok(PolicyApplication {
                        scope_root,
                        scope_depth: scope_depth_value,
                        policy_index: policy_index_value,
                        input,
                        targets,
                        output,
                    })
                });
            }
        }

        future::try_join_all(invocations).await
    }
    .await;

    let finish_result = session.finish().await;
    match (collected, finish_result) {
        (Ok(collected), Ok(())) => Ok(collected),
        (Ok(_), Err(source)) => Err(Error::StopGovernance { source }),
        (Err(err), _) => Err(err),
    }
}

#[cfg(test)]
fn build_policy_input(scenario: &Scenario, scope: &GovernedScope) -> Result<PolicyInput, Error> {
    Ok(build_scope_artifacts(scenario, scope)?.input)
}

fn build_scope_artifacts(
    scenario: &Scenario,
    scope: &GovernedScope,
) -> Result<ScopeArtifacts, Error> {
    let mut next_attachment = 0u64;
    let mut in_scope = HashSet::new();
    let mut components = Vec::new();
    let mut targets = BTreeMap::new();

    for (id, component) in scenario.components_iter() {
        if !moniker_in_scope(&component.moniker, &scope.root_moniker) {
            continue;
        }
        in_scope.insert(id);
        components.push(component.clone());
    }

    let mut bindings = Vec::new();
    let mut imports = Vec::new();
    let mut exports = Vec::new();

    for (binding_index, binding) in scenario.bindings.iter().enumerate() {
        let target_in_scope = in_scope.contains(&binding.to.component);
        let source_in_scope = binding_source_component_id(&binding.from)
            .is_some_and(|component| in_scope.contains(&component));

        if !target_in_scope && !source_in_scope {
            continue;
        }

        let capability = binding_capability(scenario, binding, &scope.root_moniker)?;
        let id = AttachmentId(next_attachment);
        next_attachment += 1;
        let side = match (source_in_scope, target_in_scope) {
            (true, true) => AttachmentSide::Common,
            (true, false) => AttachmentSide::Source,
            (false, true) => AttachmentSide::Target,
            (false, false) => unreachable!("filtered above"),
        };
        targets.insert(
            id,
            TargetDescriptor {
                key: TargetKey::Binding(binding_index),
                side,
            },
        );

        match (source_in_scope, target_in_scope) {
            (true, true) => {
                let from = scope_binding_from(&binding.from)
                    .expect("in-scope binding source should be representable");
                bindings.push(ScopeBinding {
                    id,
                    from,
                    to: binding.to.clone(),
                    capability,
                });
            }
            (false, true) => {
                imports.push(ScopeImport {
                    id,
                    to: binding.to.clone(),
                    capability,
                });
            }
            (true, false) => {
                let from = scope_binding_from(&binding.from)
                    .expect("in-scope binding source should be representable");
                exports.push(ScopeExport {
                    id,
                    from,
                    capability,
                });
            }
            (false, false) => unreachable!("filtered above"),
        }
    }

    for (export_index, export) in scenario.exports.iter().enumerate() {
        if !in_scope.contains(&export.from.component) {
            continue;
        }
        let id = AttachmentId(next_attachment);
        exports.push(ScopeExport {
            id,
            from: ScopeBindingFrom::Component(export.from.clone()),
            capability: export.capability.clone(),
        });
        targets.insert(
            id,
            TargetDescriptor {
                key: TargetKey::Export(export_index),
                side: AttachmentSide::Source,
            },
        );
        next_attachment += 1;
    }

    Ok(ScopeArtifacts {
        input: ScenarioScope {
            components,
            bindings,
            imports,
            exports,
        },
        targets,
    })
}

fn rewrite_scenario(
    mut scenario: Scenario,
    applications: &[PolicyApplication],
) -> Result<Scenario, Error> {
    if applications
        .iter()
        .all(|application| application.output.interpositions.is_empty())
    {
        return Ok(scenario);
    }

    let mut attachments_by_target: BTreeMap<TargetKey, Vec<PendingAttachment>> = BTreeMap::new();

    for (application_index, application) in applications.iter().enumerate() {
        for (interposition_index, interposition) in
            application.output.interpositions.iter().enumerate()
        {
            let component_id = insert_interposer_component(
                &mut scenario,
                application,
                application_index,
                interposition_index,
                interposition,
            )?;

            for attachment in &interposition.attachments {
                let descriptor = application.targets.get(&attachment.target).ok_or_else(|| {
                    Error::MissingAttachmentTarget {
                        scope_root: application.scope_root.clone(),
                        target: attachment.target,
                    }
                })?;
                attachments_by_target
                    .entry(descriptor.key)
                    .or_default()
                    .push(PendingAttachment {
                        scope_root: application.scope_root.clone(),
                        scope_depth: application.scope_depth,
                        policy_index: application.policy_index,
                        side: descriptor.side,
                        component: component_id,
                        interposer_slot: attachment.interposer_slot.to_string(),
                        interposer_provide: attachment.interposer_provide.to_string(),
                    });
            }
        }
    }

    let original_bindings = std::mem::take(&mut scenario.bindings);
    let original_exports = std::mem::take(&mut scenario.exports);
    let mut rewritten_bindings = Vec::with_capacity(original_bindings.len());

    for (binding_index, binding) in original_bindings.into_iter().enumerate() {
        let Some(mut chain) = attachments_by_target.remove(&TargetKey::Binding(binding_index))
        else {
            rewritten_bindings.push(binding);
            continue;
        };
        sort_attachments_for_target(&mut chain);
        rewritten_binding_chain(&mut rewritten_bindings, binding, &chain);
    }

    let mut rewritten_exports = Vec::with_capacity(original_exports.len());
    for (export_index, export) in original_exports.into_iter().enumerate() {
        let Some(mut chain) = attachments_by_target.remove(&TargetKey::Export(export_index)) else {
            rewritten_exports.push(export);
            continue;
        };
        sort_attachments_for_target(&mut chain);
        rewritten_export_chain(
            &mut rewritten_bindings,
            &mut rewritten_exports,
            export,
            &chain,
        );
    }

    scenario.bindings = rewritten_bindings;
    scenario.exports = rewritten_exports;
    scenario.normalize_order();
    // Reuse the canonical Scenario IR validators for the fully rewritten graph.
    Scenario::try_from(ScenarioIr::from(&scenario)).map_err(Error::InvalidRewrittenScenario)
}

fn insert_interposer_component(
    scenario: &mut Scenario,
    application: &PolicyApplication,
    application_index: usize,
    interposition_index: usize,
    interposition: &crate::policy::Interposition,
) -> Result<ComponentId, Error> {
    let parent = scope_root_component_id(scenario, &application.scope_root);
    let moniker =
        unique_interposer_moniker(scenario, parent, application_index, interposition_index);
    let component_id = ComponentId(scenario.components.len());

    scenario.components.push(Some(Component {
        id: component_id,
        parent: Some(parent),
        moniker: Moniker::from(moniker),
        // Synthetic interposers are post-manifest IR components, so reuse an existing digest.
        digest: scenario.component(scenario.root).digest,
        config: interposition.interposer.config.clone(),
        config_schema: interposition.interposer.config_schema.clone(),
        program: interposition.interposer.program.clone(),
        slots: interposition
            .interposer
            .slots
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect(),
        provides: interposition
            .interposer
            .provides
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect(),
        resources: interposition
            .interposer
            .resources
            .iter()
            .map(|(name, decl)| {
                (
                    name.to_string(),
                    amber_scenario::ResourceDecl {
                        kind: decl.kind,
                        params: amber_scenario::StorageResourceParams {
                            size: decl.params.size.as_ref().map(ToString::to_string),
                            retention: decl.params.retention.as_ref().map(ToString::to_string),
                            sharing: decl.params.sharing.as_ref().map(ToString::to_string),
                        },
                    },
                )
            })
            .collect(),
        metadata: interposition.interposer.metadata.clone(),
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    }));
    scenario.component_mut(parent).children.push(component_id);
    Ok(component_id)
}

fn unique_interposer_moniker(
    scenario: &Scenario,
    parent: ComponentId,
    application_index: usize,
    interposition_index: usize,
) -> String {
    let parent_moniker = scenario.component(parent).moniker.as_str();
    let base_name = format!("__policy_{application_index}_{interposition_index}");
    let base = if parent_moniker == "/" {
        format!("/{base_name}")
    } else {
        format!("{parent_moniker}/{base_name}")
    };
    if !scenario
        .components_iter()
        .any(|(_, component)| component.moniker.as_str() == base)
    {
        return base;
    }

    let mut suffix = 1usize;
    loop {
        let candidate = format!("{base}_{suffix}");
        if !scenario
            .components_iter()
            .any(|(_, component)| component.moniker.as_str() == candidate)
        {
            return candidate;
        }
        suffix += 1;
    }
}

fn scope_root_component_id(scenario: &Scenario, root_moniker: &Moniker) -> ComponentId {
    scenario
        .components_iter()
        .find_map(|(id, component)| (component.moniker == *root_moniker).then_some(id))
        .expect("governed scope root should exist in the scenario")
}

fn sort_attachments_for_target(attachments: &mut [PendingAttachment]) {
    attachments.sort_by(|left, right| {
        side_sort_key(left.side, left.scope_depth)
            .cmp(&side_sort_key(right.side, right.scope_depth))
            .then_with(|| left.policy_index.cmp(&right.policy_index))
            .then_with(|| left.scope_root.as_str().cmp(right.scope_root.as_str()))
    });
}

fn side_sort_key(side: AttachmentSide, scope_depth: usize) -> (u8, usize) {
    match side {
        AttachmentSide::Source => (0, usize::MAX - scope_depth),
        AttachmentSide::Common => (1, usize::MAX - scope_depth),
        AttachmentSide::Target => (2, scope_depth),
    }
}

fn rewritten_binding_chain(
    bindings: &mut Vec<BindingEdge>,
    original: BindingEdge,
    chain: &[PendingAttachment],
) {
    let mut from = original.from;
    let weak = original.weak;

    for attachment in chain {
        bindings.push(BindingEdge {
            from,
            to: SlotRef {
                component: attachment.component,
                name: attachment.interposer_slot.clone(),
            },
            weak,
        });
        from = BindingFrom::Component(ProvideRef {
            component: attachment.component,
            name: attachment.interposer_provide.clone(),
        });
    }

    bindings.push(BindingEdge {
        from,
        to: original.to,
        weak,
    });
}

fn rewritten_export_chain(
    bindings: &mut Vec<BindingEdge>,
    exports: &mut Vec<ScenarioExport>,
    original: ScenarioExport,
    chain: &[PendingAttachment],
) {
    let mut from = BindingFrom::Component(original.from.clone());

    for attachment in chain {
        bindings.push(BindingEdge {
            from,
            to: SlotRef {
                component: attachment.component,
                name: attachment.interposer_slot.clone(),
            },
            weak: false,
        });
        from = BindingFrom::Component(ProvideRef {
            component: attachment.component,
            name: attachment.interposer_provide.clone(),
        });
    }

    let BindingFrom::Component(final_from) = from else {
        unreachable!("export rewrite should always end with a component provide");
    };
    exports.push(ScenarioExport {
        name: original.name,
        capability: original.capability,
        from: final_from,
    });
}

fn moniker_in_scope(candidate: &Moniker, root: &Moniker) -> bool {
    let candidate = candidate.as_str();
    let root = root.as_str();
    if root == "/" {
        return true;
    }
    candidate == root
        || candidate
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn scope_depth(moniker: &Moniker) -> usize {
    moniker
        .as_str()
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count()
}

fn binding_source_component_id(from: &BindingFrom) -> Option<ComponentId> {
    match from {
        BindingFrom::Component(provide) => Some(provide.component),
        BindingFrom::Resource(resource) => Some(resource.component),
        BindingFrom::Framework(framework) => Some(framework.authority),
        BindingFrom::External(_) => None,
    }
}

fn scope_binding_from(from: &BindingFrom) -> Option<ScopeBindingFrom> {
    match from {
        BindingFrom::Component(provide) => Some(ScopeBindingFrom::Component(provide.clone())),
        BindingFrom::Resource(resource) => Some(ScopeBindingFrom::Resource(resource.clone())),
        BindingFrom::Framework(framework) => Some(ScopeBindingFrom::Framework(framework.clone())),
        BindingFrom::External(_) => None,
    }
}

fn binding_capability(
    scenario: &Scenario,
    binding: &amber_scenario::BindingEdge,
    root_moniker: &Moniker,
) -> Result<CapabilityDecl, Error> {
    let target_component = scenario.component(binding.to.component);
    let slot_decl = target_component
        .slots
        .get(binding.to.name.as_str())
        .ok_or_else(|| Error::MissingTargetSlot {
            root_moniker: root_moniker.clone(),
            component: target_component.moniker.clone(),
            slot: binding.to.name.clone(),
        })?;
    Ok(slot_decl.decl.clone())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use amber_manifest::{
        CapabilityDecl, CapabilityKind, ExportName, ManifestDigest, ProvideDecl, ProvideName,
        SlotDecl, SlotName,
    };
    use amber_scenario::{
        BindingEdge, Component, Moniker, Program, ProgramCommon, ProgramPath, ProvideRef,
        ScenarioExport,
    };

    use super::*;
    use crate::{
        governance_runtime::{
            GovernanceFuture, GovernanceRuntime, GovernanceRuntimeError, GovernanceSession,
        },
        policy::{Attachment, InterposerComponent, Interposition},
    };

    #[derive(Default)]
    struct MockRunner {
        outputs: BTreeMap<String, PolicyOutput>,
    }

    impl GovernanceRuntime for MockRunner {
        fn start<'a>(
            &'a self,
            _compiled: &'a CompiledScenario,
        ) -> GovernanceFuture<'a, Result<Box<dyn GovernanceSession>, GovernanceRuntimeError>>
        {
            Box::pin(async move {
                Ok(Box::new(MockSession {
                    outputs: self.outputs.clone(),
                }) as Box<dyn GovernanceSession>)
            })
        }
    }

    struct MockSession {
        outputs: BTreeMap<String, PolicyOutput>,
    }

    impl GovernanceSession for MockSession {
        fn invoke_policy<'a>(
            &'a self,
            policy_export: &'a ExportName,
            _request: &'a PolicyRequest,
        ) -> GovernanceFuture<'a, Result<PolicyOutput, GovernanceRuntimeError>> {
            Box::pin(async move {
                Ok(self
                    .outputs
                    .get(policy_export.as_str())
                    .cloned()
                    .unwrap_or_default())
            })
        }

        fn finish(
            self: Box<Self>,
        ) -> GovernanceFuture<'static, Result<(), GovernanceRuntimeError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn build_policy_input_classifies_bindings_imports_and_exports() {
        let scenario = fixture_scenario();
        let scope = GovernedScope {
            root_moniker: moniker("/left"),
            policies: Vec::new(),
        };

        let input = build_policy_input(&scenario, &scope).expect("policy input");

        assert_eq!(input.components.len(), 2);
        assert_eq!(input.imports.len(), 1);
        assert_eq!(input.bindings.len(), 1);
        assert_eq!(input.exports.len(), 2);

        assert_eq!(input.imports[0].to.component, ComponentId(1));
        assert_eq!(input.bindings[0].to.component, ComponentId(2));
        assert!(matches!(
            input.exports[0].from,
            ScopeBindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                ..
            })
        ));
        assert!(matches!(
            input.exports[1].from,
            ScopeBindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                ..
            })
        ));

        let mut ids = HashSet::new();
        for id in input
            .imports
            .iter()
            .map(|edge| edge.id)
            .chain(input.bindings.iter().map(|edge| edge.id))
            .chain(input.exports.iter().map(|edge| edge.id))
        {
            assert!(ids.insert(id), "attachment ids should be unique");
        }
    }

    #[tokio::test]
    async fn apply_policies_returns_original_scenario_for_empty_outputs() {
        let scenario = fixture_scenario();
        let governance = fixture_governance();
        let rewritten = apply_policies(
            scenario.clone(),
            Some(&governance),
            Some(&MockRunner::default()),
        )
        .await
        .expect("empty outputs should keep scenario unchanged");

        assert_eq!(rewritten, scenario);
    }

    #[tokio::test]
    async fn apply_policies_rewrites_import_binding_chain_for_non_empty_outputs() {
        let scenario = fixture_scenario();
        let governance = fixture_governance();

        let runner = MockRunner {
            // In fixture_scenario, AttachmentId(0) is the import edge /src.api -> /left.in.
            outputs: BTreeMap::from([("policy_0_0".to_string(), valid_output(AttachmentId(0)))]),
        };

        let rewritten = apply_policies(scenario, Some(&governance), Some(&runner))
            .await
            .expect("non-empty outputs should rewrite the binding");

        assert_eq!(rewritten.bindings.len(), 4);
        assert!(rewritten.bindings.iter().any(|binding| matches!(
            &binding.from,
            BindingFrom::Component(ProvideRef {
                component: ComponentId(3),
                name,
            }) if name == "api"
        ) && binding.to.component.0 == 5
            && binding.to.name == "in"));
        assert!(rewritten.bindings.iter().any(|binding| matches!(
            &binding.from,
            BindingFrom::Component(ProvideRef {
                component: ComponentId(5),
                name,
            }) if name == "out"
        ) && binding.to.component
            == ComponentId(1)
            && binding.to.name == "in"));
        assert_eq!(
            rewritten.component(ComponentId(5)).parent,
            Some(ComponentId(1))
        );
    }

    #[tokio::test]
    async fn apply_policies_rewrites_scenario_exports() {
        let scenario = fixture_scenario();
        let governance = fixture_governance();

        let runner = MockRunner {
            outputs: BTreeMap::from([("policy_0_0".to_string(), valid_output(AttachmentId(3)))]),
        };

        let rewritten = apply_policies(scenario, Some(&governance), Some(&runner))
            .await
            .expect("export target should be rewritten");

        assert!(rewritten.bindings.iter().any(|binding| matches!(
            &binding.from,
            BindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                name,
            }) if name == "out"
        ) && binding.to.component.0 == 5
            && binding.to.name == "in"));
        assert_eq!(rewritten.exports.len(), 1);
        assert_eq!(rewritten.exports[0].from.component, ComponentId(5));
        assert_eq!(rewritten.exports[0].from.name, "out");
    }

    #[tokio::test]
    async fn apply_policies_preserves_interposer_config() {
        let scenario = fixture_scenario();
        let governance = fixture_governance();

        let runner = MockRunner {
            outputs: BTreeMap::from([(
                "policy_0_0".to_string(),
                PolicyOutput {
                    interpositions: vec![Interposition {
                        interposer: InterposerComponent {
                            config: Some(serde_json::json!({
                                "redaction_terms": ["${config.secret}"],
                            })),
                            config_schema: Some(serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "redaction_terms": {
                                        "type": "array",
                                        "items": { "type": "string" },
                                    },
                                },
                                "required": ["redaction_terms"],
                            })),
                            program: Some(Program::Path(ProgramPath {
                                path: "./interposer".to_string(),
                                args: amber_manifest::ProgramEntrypoint::default(),
                                common: ProgramCommon::default(),
                            })),
                            slots: BTreeMap::from([(
                                SlotName::try_from("in").expect("valid slot name"),
                                SlotDecl::builder()
                                    .decl(http_capability())
                                    .optional(false)
                                    .multiple(false)
                                    .build(),
                            )]),
                            provides: BTreeMap::from([(
                                ProvideName::try_from("out").expect("valid provide name"),
                                ProvideDecl::builder().decl(http_capability()).build(),
                            )]),
                            resources: BTreeMap::new(),
                            metadata: None,
                        },
                        attachments: vec![Attachment {
                            target: AttachmentId(0),
                            interposer_slot: SlotName::try_from("in").expect("valid slot name"),
                            interposer_provide: ProvideName::try_from("out")
                                .expect("valid provide name"),
                        }],
                    }],
                },
            )]),
        };

        let rewritten = apply_policies(scenario, Some(&governance), Some(&runner))
            .await
            .expect("config-bearing interposer should rewrite successfully");

        let interposer = rewritten.component(ComponentId(5));
        assert_eq!(
            interposer.config,
            Some(serde_json::json!({
                "redaction_terms": ["${config.secret}"],
            }))
        );
        assert_eq!(
            interposer.config_schema,
            Some(serde_json::json!({
                "type": "object",
                "properties": {
                    "redaction_terms": {
                        "type": "array",
                        "items": { "type": "string" },
                    },
                },
                "required": ["redaction_terms"],
            }))
        );
    }

    #[tokio::test]
    async fn apply_policies_orders_cross_scope_interposers_by_side_and_depth() {
        let scenario = cross_scope_fixture_scenario();
        let governance = Governance {
            scenario: governance_fixture_scenario(),
            provenance: Default::default(),
            scopes: vec![
                GovernedScope {
                    root_moniker: moniker("/"),
                    policies: vec![governed_policy("root_policy")],
                },
                GovernedScope {
                    root_moniker: moniker("/right"),
                    policies: vec![governed_policy("right_policy")],
                },
                GovernedScope {
                    root_moniker: moniker("/left"),
                    policies: vec![governed_policy("left_policy")],
                },
            ],
        };
        let runner = MockRunner {
            outputs: BTreeMap::from([
                // Each scope sees the single binding in its local input as AttachmentId(0).
                ("root_policy".to_string(), valid_output(AttachmentId(0))),
                ("right_policy".to_string(), valid_output(AttachmentId(0))),
                ("left_policy".to_string(), valid_output(AttachmentId(0))),
            ]),
        };

        let rewritten = apply_policies(scenario, Some(&governance), Some(&runner))
            .await
            .expect("cross-scope outputs should rewrite the binding");

        assert_eq!(rewritten.bindings.len(), 4);
        assert_eq!(
            rewritten.bindings[0],
            component_binding((1, "out"), (5, "in"))
        );
        assert_eq!(
            rewritten.bindings[1],
            component_binding((5, "out"), (3, "in"))
        );
        assert_eq!(
            rewritten.bindings[2],
            component_binding((3, "out"), (4, "in"))
        );
        assert_eq!(
            rewritten.bindings[3],
            component_binding((4, "out"), (2, "in"))
        );
    }

    #[tokio::test]
    async fn apply_policies_orders_same_scope_policies_by_declaration_order() {
        let scenario = fixture_scenario();
        let governance = Governance {
            scenario: governance_fixture_scenario(),
            provenance: Default::default(),
            scopes: vec![GovernedScope {
                root_moniker: moniker("/left"),
                policies: vec![governed_policy("policy_a"), governed_policy("policy_b")],
            }],
        };
        let runner = MockRunner {
            outputs: BTreeMap::from([
                // In fixture_scenario, AttachmentId(0) is the import edge /src.api -> /left.in.
                ("policy_a".to_string(), valid_output(AttachmentId(0))),
                ("policy_b".to_string(), valid_output(AttachmentId(0))),
            ]),
        };

        let rewritten = apply_policies(scenario, Some(&governance), Some(&runner))
            .await
            .expect("same-scope outputs should rewrite in declaration order");

        assert_eq!(rewritten.bindings.len(), 5);
        assert_eq!(
            rewritten.bindings[0],
            component_binding((3, "api"), (5, "in"))
        );
        assert_eq!(
            rewritten.bindings[1],
            component_binding((5, "out"), (6, "in"))
        );
        assert_eq!(
            rewritten.bindings[2],
            component_binding((6, "out"), (1, "in"))
        );
    }

    fn fixture_governance() -> Governance {
        Governance {
            scenario: governance_fixture_scenario(),
            provenance: Default::default(),
            scopes: vec![GovernedScope {
                root_moniker: moniker("/left"),
                policies: vec![governed_policy("policy_0_0")],
            }],
        }
    }

    fn fixture_scenario() -> Scenario {
        let http_slot = SlotDecl::builder()
            .decl(http_capability())
            .optional(false)
            .multiple(false)
            .build();
        let http_provide = ProvideDecl::builder().decl(http_capability()).build();

        let root = component(0, "/", None);
        let left = component_with_caps(
            1,
            "/left",
            Some(ComponentId(0)),
            BTreeMap::from([("in".to_string(), http_slot.clone())]),
            BTreeMap::from([("out".to_string(), http_provide.clone())]),
        );
        let worker = component_with_caps(
            2,
            "/left/worker",
            Some(ComponentId(1)),
            BTreeMap::from([("needs".to_string(), http_slot.clone())]),
            BTreeMap::new(),
        );
        let src = component_with_caps(
            3,
            "/src",
            Some(ComponentId(0)),
            BTreeMap::new(),
            BTreeMap::from([("api".to_string(), http_provide.clone())]),
        );
        let sink = component_with_caps(
            4,
            "/sink",
            Some(ComponentId(0)),
            BTreeMap::from([("in".to_string(), http_slot.clone())]),
            BTreeMap::new(),
        );

        let mut scenario = Scenario {
            root: ComponentId(0),
            components: vec![Some(root), Some(left), Some(worker), Some(src), Some(sink)],
            bindings: vec![
                BindingEdge {
                    from: BindingFrom::Component(ProvideRef {
                        component: ComponentId(3),
                        name: "api".to_string(),
                    }),
                    to: amber_scenario::SlotRef {
                        component: ComponentId(1),
                        name: "in".to_string(),
                    },
                    weak: false,
                },
                BindingEdge {
                    from: BindingFrom::Component(ProvideRef {
                        component: ComponentId(1),
                        name: "out".to_string(),
                    }),
                    to: amber_scenario::SlotRef {
                        component: ComponentId(2),
                        name: "needs".to_string(),
                    },
                    weak: false,
                },
                BindingEdge {
                    from: BindingFrom::Component(ProvideRef {
                        component: ComponentId(1),
                        name: "out".to_string(),
                    }),
                    to: amber_scenario::SlotRef {
                        component: ComponentId(4),
                        name: "in".to_string(),
                    },
                    weak: false,
                },
            ],
            exports: vec![ScenarioExport {
                name: "api".to_string(),
                capability: http_capability(),
                from: ProvideRef {
                    component: ComponentId(1),
                    name: "out".to_string(),
                },
            }],
            manifest_catalog: BTreeMap::new(),
        };

        scenario.component_mut(ComponentId(0)).children =
            vec![ComponentId(1), ComponentId(3), ComponentId(4)];
        scenario.component_mut(ComponentId(1)).children = vec![ComponentId(2)];
        scenario.normalize_order();
        scenario
    }

    fn governance_fixture_scenario() -> Scenario {
        Scenario {
            root: ComponentId(0),
            components: vec![Some(component(0, "/", None))],
            bindings: Vec::new(),
            exports: Vec::new(),
            manifest_catalog: BTreeMap::new(),
        }
    }

    fn cross_scope_fixture_scenario() -> Scenario {
        let http_slot = SlotDecl::builder()
            .decl(http_capability())
            .optional(false)
            .multiple(false)
            .build();
        let http_provide = ProvideDecl::builder().decl(http_capability()).build();

        let root = component(0, "/", None);
        let left = component_with_caps(
            1,
            "/left",
            Some(ComponentId(0)),
            BTreeMap::new(),
            BTreeMap::from([("out".to_string(), http_provide.clone())]),
        );
        let right = component_with_caps(
            2,
            "/right",
            Some(ComponentId(0)),
            BTreeMap::from([("in".to_string(), http_slot)]),
            BTreeMap::new(),
        );

        let mut scenario = Scenario {
            root: ComponentId(0),
            components: vec![Some(root), Some(left), Some(right)],
            bindings: vec![BindingEdge {
                from: BindingFrom::Component(ProvideRef {
                    component: ComponentId(1),
                    name: "out".to_string(),
                }),
                to: amber_scenario::SlotRef {
                    component: ComponentId(2),
                    name: "in".to_string(),
                },
                weak: false,
            }],
            exports: Vec::new(),
            manifest_catalog: BTreeMap::new(),
        };
        scenario.component_mut(ComponentId(0)).children = vec![ComponentId(1), ComponentId(2)];
        scenario.normalize_order();
        scenario
    }

    fn valid_output(target: AttachmentId) -> PolicyOutput {
        PolicyOutput {
            interpositions: vec![Interposition {
                interposer: InterposerComponent {
                    config: None,
                    config_schema: None,
                    program: Some(Program::Path(ProgramPath {
                        path: "./interposer".to_string(),
                        args: amber_manifest::ProgramEntrypoint::default(),
                        common: ProgramCommon::default(),
                    })),
                    slots: BTreeMap::from([(
                        SlotName::try_from("in").expect("valid slot name"),
                        SlotDecl::builder()
                            .decl(http_capability())
                            .optional(false)
                            .multiple(false)
                            .build(),
                    )]),
                    provides: BTreeMap::from([(
                        ProvideName::try_from("out").expect("valid provide name"),
                        ProvideDecl::builder().decl(http_capability()).build(),
                    )]),
                    resources: BTreeMap::new(),
                    metadata: None,
                },
                attachments: vec![Attachment {
                    target,
                    interposer_slot: SlotName::try_from("in").expect("valid slot name"),
                    interposer_provide: ProvideName::try_from("out").expect("valid provide name"),
                }],
            }],
        }
    }

    fn component_binding(from: (usize, &str), to: (usize, &str)) -> BindingEdge {
        BindingEdge {
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(from.0),
                name: from.1.to_string(),
            }),
            to: amber_scenario::SlotRef {
                component: ComponentId(to.0),
                name: to.1.to_string(),
            },
            weak: false,
        }
    }

    fn component(id: usize, moniker: &str, parent: Option<ComponentId>) -> Component {
        component_with_caps(id, moniker, parent, BTreeMap::new(), BTreeMap::new())
    }

    fn component_with_caps(
        id: usize,
        path: &str,
        parent: Option<ComponentId>,
        slots: BTreeMap<String, SlotDecl>,
        provides: BTreeMap<String, ProvideDecl>,
    ) -> Component {
        Component {
            id: ComponentId(id),
            parent,
            moniker: moniker(path),
            digest: digest(id as u8),
            config: None,
            config_schema: None,
            program: None,
            slots,
            provides,
            resources: BTreeMap::new(),
            metadata: None,
            child_templates: BTreeMap::new(),
            children: Vec::new(),
        }
    }

    fn digest(byte: u8) -> ManifestDigest {
        ManifestDigest::new([byte; 32])
    }

    fn http_capability() -> CapabilityDecl {
        CapabilityDecl::builder().kind(CapabilityKind::Http).build()
    }

    fn governed_policy(name: &str) -> crate::governance::GovernedPolicy {
        crate::governance::GovernedPolicy {
            export: ExportName::try_from(name).expect("valid export name"),
        }
    }

    fn moniker(path: &str) -> Moniker {
        Moniker::from(Arc::from(path))
    }
}
