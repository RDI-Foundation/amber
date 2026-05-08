use std::collections::{BTreeMap, BTreeSet, HashSet};

use amber_manifest::{CapabilityDecl, ExperimentalFeature};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, Scenario,
    ScenarioExport, ScenarioIr, ScenarioIrError, SlotRef,
};
use amber_scenario_runner::{
    JSON_EXPORT_RESPONSE_PREVIEW_BYTES, ScenarioRunOptions, ScenarioRunner, ScenarioRunnerError,
    response_body_preview,
};
use futures::future;
use miette::Diagnostic;
use thiserror::Error;

use crate::{
    OverlayPlan, OverlayScopePlan,
    config::analysis::ScenarioConfigAnalysis,
    overlay::{
        AttachmentId, InterpositionPlan, OverlayRequest, ScenarioScope, ScopeBinding,
        ScopeBindingFrom, ScopeExport, ScopeImport, ValidationError,
        validate_interposer_program_ir, validate_interposition_plan_for_scope,
    },
    reporter::{CompiledScenario, CompiledScenarioError},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OverlayInvocation {
    pub scope_root: Moniker,
    pub scope_depth: usize,
    pub overlay_index: usize,
    pub overlay_display_name: String,
    pub input: ScenarioScope,
    targets: BTreeMap<AttachmentId, TargetDescriptor>,
    pub plan: InterpositionPlan,
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
    overlay_index: usize,
    side: AttachmentSide,
    component: ComponentId,
    interposer_slot: String,
    interposer_provide: String,
}

struct ScopeArtifacts {
    input: ScenarioScope,
    targets: BTreeMap<AttachmentId, TargetDescriptor>,
}

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum Error {
    #[error(
        "binding target `{component}.{slot}` is missing while building overlay input for scope \
         `{root_moniker}`"
    )]
    #[diagnostic(code(compiler::overlay_pass_missing_target_slot))]
    MissingTargetSlot {
        root_moniker: Moniker,
        component: Moniker,
        slot: String,
    },

    #[error(
        "overlays require a scenario runner, but none was configured while compiling scope \
         `{scope_root}`"
    )]
    #[diagnostic(code(compiler::overlay_pass_missing_scenario_runner))]
    MissingScenarioRunner { scope_root: Moniker },

    #[error("failed to start overlay scenario: {source}")]
    #[diagnostic(code(compiler::overlay_pass_start_overlay_scenario))]
    StartOverlayScenario {
        #[source]
        source: ScenarioRunnerError,
    },

    #[error("failed to compile overlay scenario")]
    #[diagnostic(code(compiler::overlay_pass_compile_overlay_scenario))]
    CompileOverlayScenario {
        #[source]
        source: CompiledScenarioError,
    },

    #[error("failed to stop overlay scenario: {source}")]
    #[diagnostic(code(compiler::overlay_pass_stop_overlay_scenario))]
    StopOverlayScenario {
        #[source]
        source: ScenarioRunnerError,
    },

    #[error("overlay `{overlay}` in scope `{scope_root}` failed")]
    #[diagnostic(code(compiler::overlay_pass_invoke_overlay))]
    InvokeOverlay {
        scope_root: Moniker,
        overlay: String,
        #[source]
        source: ScenarioRunnerError,
    },

    #[error("failed to serialize request for overlay `{overlay}` in scope `{scope_root}`")]
    #[diagnostic(code(compiler::overlay_pass_overlay_request_serialize))]
    OverlayRequestSerialize {
        scope_root: Moniker,
        overlay: String,
        #[source]
        source: serde_json::Error,
    },

    #[error(
        "overlay `{overlay}` in scope `{scope_root}` returned response body that was not valid \
         JSON: {source}\n\nbody preview:\n{body_preview}"
    )]
    #[diagnostic(code(compiler::overlay_pass_interposition_plan_deserialize))]
    OverlayResponseInvalidJson {
        scope_root: Moniker,
        overlay: String,
        #[source]
        source: serde_json::Error,
        body_preview: String,
    },

    #[error(
        "overlay `{overlay}` in scope `{scope_root}` returned JSON that did not match \
         interposition plan schema at {path} (line {line}, column {column})"
    )]
    #[diagnostic(code(compiler::overlay_pass_interposition_plan_deserialize))]
    OverlayResponseDeserialize {
        scope_root: Moniker,
        overlay: String,
        path: String,
        line: usize,
        column: usize,
    },

    #[error("overlay `{overlay}` in scope `{scope_root}` returned an invalid interposition plan")]
    #[diagnostic(code(compiler::overlay_pass_invalid_interposition_plan))]
    InvalidInterpositionPlan {
        scope_root: Moniker,
        overlay: String,
        #[source]
        source: Box<ValidationError>,
    },

    #[error("scenario config analysis failed before overlay execution: {message}")]
    #[diagnostic(code(compiler::overlay_pass_config_analysis_failed))]
    ConfigAnalysisFailed { message: String },

    #[error("attachment target {target} is missing while rewriting scope `{scope_root}`")]
    #[diagnostic(code(compiler::overlay_pass_missing_attachment_target))]
    MissingAttachmentTarget {
        scope_root: Moniker,
        target: AttachmentId,
    },

    #[error(transparent)]
    #[diagnostic(code(compiler::overlay_pass_invalid_rewritten_scenario))]
    InvalidRewrittenScenario(#[from] ScenarioIrError),
}

pub(crate) async fn apply_overlays(
    scenario: Scenario,
    overlays: Option<&OverlayPlan>,
    runner: Option<&dyn ScenarioRunner<CompiledScenario>>,
) -> Result<Scenario, Error> {
    let Some(overlays) = overlays else {
        return Ok(scenario);
    };
    if overlays.scopes.is_empty() {
        return Ok(scenario);
    }
    let Some(runner) = runner else {
        return Err(Error::MissingScenarioRunner {
            scope_root: overlays.scopes[0].root_moniker.clone(),
        });
    };

    let collected = collect_interposition_plans(&scenario, overlays, runner).await?;
    rewrite_scenario(scenario, &collected)
}

async fn collect_interposition_plans(
    scenario: &Scenario,
    overlays: &OverlayPlan,
    runner: &dyn ScenarioRunner<CompiledScenario>,
) -> Result<Vec<OverlayInvocation>, Error> {
    let config_analysis = ScenarioConfigAnalysis::from_scenario(scenario)
        .map_err(|message| Error::ConfigAnalysisFailed { message })?;
    if let Some(err) = config_analysis.template_errors().first() {
        return Err(Error::ConfigAnalysisFailed {
            message: err.message.clone(),
        });
    }

    let compiled =
        CompiledScenario::from_scenario_with_provenance(&overlays.scenario, &overlays.provenance)
            .map_err(|source| Error::CompileOverlayScenario { source })?;
    let options = ScenarioRunOptions {
        export_display_names: overlays
            .scopes
            .iter()
            .flat_map(|scope| scope.overlays.iter())
            .map(|overlay| (overlay.export.to_string(), overlay.display_name.clone()))
            .collect(),
    };
    let run = runner
        .start(&compiled, options)
        .await
        .map_err(|source| Error::StartOverlayScenario { source })?;
    let run_ref = run.as_ref();
    let collected = async {
        let mut invocations = Vec::new();

        for scope in &overlays.scopes {
            let ScopeArtifacts { input, targets } = build_scope_artifacts(scenario, scope)?;
            let scope_depth_value = scope_depth(&scope.root_moniker);
            let scope_root = scope_root_component_id(scenario, &scope.root_moniker);
            let scope_config = config_analysis.expect_component(scope_root);

            for (overlay_index, overlay) in scope.overlays.iter().enumerate() {
                let scope_root = scope.root_moniker.clone();
                let overlay_index_value = overlay_index;
                let overlay_export = overlay.export.clone();
                let overlay_display_name = overlay.display_name.clone();
                let request = OverlayRequest {
                    scope: input.clone(),
                };
                let input = input.clone();
                let targets = targets.clone();

                invocations.push(async move {
                    let request_json = serde_json::to_value(&request).map_err(|source| {
                        Error::OverlayRequestSerialize {
                            scope_root: scope_root.clone(),
                            overlay: overlay_display_name.clone(),
                            source,
                        }
                    })?;
                    let body = run_ref
                        .post_json_export(&overlay_export, &request_json)
                        .await
                        .map_err(|source| Error::InvokeOverlay {
                            scope_root: scope_root.clone(),
                            overlay: overlay_display_name.clone(),
                            source,
                        })?;
                    let plan = deserialize_interposition_plan(&body).map_err(|err| match err {
                        InterpositionPlanDecodeError::InvalidJson {
                            source,
                            body_preview,
                        } => Error::OverlayResponseInvalidJson {
                            scope_root: scope_root.clone(),
                            overlay: overlay_display_name.clone(),
                            source,
                            body_preview,
                        },
                        InterpositionPlanDecodeError::InvalidShape { path, line, column } => {
                            Error::OverlayResponseDeserialize {
                                scope_root: scope_root.clone(),
                                overlay: overlay_display_name.clone(),
                                path,
                                line,
                                column,
                            }
                        }
                    })?;
                    // Generated interposers may not rely on experimental features.
                    validate_interposition_plan_for_scope(
                        &plan,
                        &input,
                        &BTreeSet::<ExperimentalFeature>::new(),
                        scope_config,
                    )
                    .map_err(|source| Error::InvalidInterpositionPlan {
                        scope_root: scope_root.clone(),
                        overlay: overlay_display_name.clone(),
                        source: Box::new(source),
                    })?;
                    Ok(OverlayInvocation {
                        scope_root,
                        scope_depth: scope_depth_value,
                        overlay_index: overlay_index_value,
                        overlay_display_name,
                        input,
                        targets,
                        plan,
                    })
                });
            }
        }

        future::try_join_all(invocations).await
    }
    .await;

    let finish_result = run.finish().await;
    match (collected, finish_result) {
        (Ok(collected), Ok(())) => Ok(collected),
        (Ok(_), Err(source)) => Err(Error::StopOverlayScenario { source }),
        (Err(err), _) => Err(err),
    }
}

enum InterpositionPlanDecodeError {
    InvalidJson {
        source: serde_json::Error,
        body_preview: String,
    },
    InvalidShape {
        path: String,
        line: usize,
        column: usize,
    },
}

fn deserialize_interposition_plan(
    body: &str,
) -> Result<InterpositionPlan, InterpositionPlanDecodeError> {
    let mut deserializer = serde_json::Deserializer::from_str(body);
    let plan = match serde_path_to_error::deserialize::<_, InterpositionPlan>(&mut deserializer) {
        Ok(plan) => plan,
        Err(source) if source.inner().is_data() => {
            return Err(InterpositionPlanDecodeError::InvalidShape {
                path: display_interposition_plan_path(source.path()),
                line: source.inner().line(),
                column: source.inner().column(),
            });
        }
        Err(source) => {
            return Err(InterpositionPlanDecodeError::InvalidJson {
                source: source.into_inner(),
                body_preview: response_body_preview(body, JSON_EXPORT_RESPONSE_PREVIEW_BYTES),
            });
        }
    };

    deserializer
        .end()
        .map_err(|source| InterpositionPlanDecodeError::InvalidJson {
            source,
            body_preview: response_body_preview(body, JSON_EXPORT_RESPONSE_PREVIEW_BYTES),
        })?;
    Ok(plan)
}

fn display_interposition_plan_path(path: &serde_path_to_error::Path) -> String {
    let path = path.to_string();
    if path.is_empty() {
        "<root>".to_string()
    } else {
        path
    }
}

#[cfg(test)]
fn build_overlay_input(
    scenario: &Scenario,
    scope: &OverlayScopePlan,
) -> Result<ScenarioScope, Error> {
    Ok(build_scope_artifacts(scenario, scope)?.input)
}

fn build_scope_artifacts(
    scenario: &Scenario,
    scope: &OverlayScopePlan,
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
    applications: &[OverlayInvocation],
) -> Result<Scenario, Error> {
    if applications
        .iter()
        .all(|application| application.plan.interpositions.is_empty())
    {
        return Ok(scenario);
    }

    let mut attachments_by_target: BTreeMap<TargetKey, Vec<PendingAttachment>> = BTreeMap::new();

    for (application_index, application) in applications.iter().enumerate() {
        for (interposition_index, interposition) in
            application.plan.interpositions.iter().enumerate()
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
                        overlay_index: application.overlay_index,
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
    application: &OverlayInvocation,
    application_index: usize,
    interposition_index: usize,
    interposition: &crate::overlay::Interposition,
) -> Result<ComponentId, Error> {
    let parent = scope_root_component_id(scenario, &application.scope_root);
    let moniker =
        unique_interposer_moniker(scenario, parent, application_index, interposition_index);
    let component_id = ComponentId(scenario.components.len());

    validate_interposer_program_ir(
        &interposition.interposer,
        component_id,
        &BTreeSet::<ExperimentalFeature>::new(),
    )
    .map_err(|source| Error::InvalidInterpositionPlan {
        scope_root: application.scope_root.clone(),
        overlay: application.overlay_display_name.clone(),
        source: Box::new(source),
    })?;

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
    let base_name = format!("__overlay_{application_index}_{interposition_index}");
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
        .expect("overlay scope root should exist in the scenario")
}

fn sort_attachments_for_target(attachments: &mut [PendingAttachment]) {
    attachments.sort_by(|left, right| {
        side_sort_key(left.side, left.scope_depth)
            .cmp(&side_sort_key(right.side, right.scope_depth))
            .then_with(|| left.overlay_index.cmp(&right.overlay_index))
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
    use amber_scenario_runner::{
        RunningScenario, ScenarioRunOptions, ScenarioRunner, ScenarioRunnerError,
        ScenarioRunnerFuture,
    };

    use super::*;
    use crate::overlay::{Attachment, InterposerComponent, Interposition};

    #[derive(Default)]
    struct MockRunner {
        plans: BTreeMap<String, InterpositionPlan>,
    }

    impl ScenarioRunner<CompiledScenario> for MockRunner {
        fn start<'a>(
            &'a self,
            _compiled: &'a CompiledScenario,
            _options: ScenarioRunOptions,
        ) -> ScenarioRunnerFuture<'a, Result<Box<dyn RunningScenario>, ScenarioRunnerError>>
        {
            Box::pin(async move {
                Ok(Box::new(MockSession {
                    plans: self.plans.clone(),
                }) as Box<dyn RunningScenario>)
            })
        }
    }

    struct MockSession {
        plans: BTreeMap<String, InterpositionPlan>,
    }

    impl RunningScenario for MockSession {
        fn post_json_export<'a>(
            &'a self,
            export: &'a ExportName,
            _request: &'a serde_json::Value,
        ) -> ScenarioRunnerFuture<'a, Result<String, ScenarioRunnerError>> {
            Box::pin(async move {
                serde_json::to_string(&self.plans.get(export.as_str()).cloned().unwrap_or_default())
                    .map_err(|err| ScenarioRunnerError::message(err.to_string()))
            })
        }

        fn finish(
            self: Box<Self>,
        ) -> ScenarioRunnerFuture<'static, Result<(), ScenarioRunnerError>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct StartFailureRunner;

    impl ScenarioRunner<CompiledScenario> for StartFailureRunner {
        fn start<'a>(
            &'a self,
            _compiled: &'a CompiledScenario,
            options: ScenarioRunOptions,
        ) -> ScenarioRunnerFuture<'a, Result<Box<dyn RunningScenario>, ScenarioRunnerError>>
        {
            Box::pin(async move {
                let display_name = options.display_name_for("overlay_0_0").to_string();
                Err(ScenarioRunnerError::message(format!(
                    "scenario exports did not become ready in time: {display_name}"
                )))
            })
        }
    }

    struct RawBodyRunner {
        body: String,
    }

    impl ScenarioRunner<CompiledScenario> for RawBodyRunner {
        fn start<'a>(
            &'a self,
            _compiled: &'a CompiledScenario,
            _options: ScenarioRunOptions,
        ) -> ScenarioRunnerFuture<'a, Result<Box<dyn RunningScenario>, ScenarioRunnerError>>
        {
            Box::pin(async move {
                Ok(Box::new(RawBodySession {
                    body: self.body.clone(),
                }) as Box<dyn RunningScenario>)
            })
        }
    }

    struct RawBodySession {
        body: String,
    }

    impl RunningScenario for RawBodySession {
        fn post_json_export<'a>(
            &'a self,
            _export: &'a ExportName,
            _request: &'a serde_json::Value,
        ) -> ScenarioRunnerFuture<'a, Result<String, ScenarioRunnerError>> {
            Box::pin(async move { Ok(self.body.clone()) })
        }

        fn finish(
            self: Box<Self>,
        ) -> ScenarioRunnerFuture<'static, Result<(), ScenarioRunnerError>> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn build_overlay_input_classifies_bindings_imports_and_exports() {
        let scenario = fixture_scenario();
        let scope = OverlayScopePlan {
            root_moniker: moniker("/left"),
            overlays: Vec::new(),
        };

        let input = build_overlay_input(&scenario, &scope).expect("overlay input");

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
    async fn apply_overlays_returns_original_scenario_for_empty_plans() {
        let scenario = fixture_scenario();
        let overlays = fixture_overlays();
        let rewritten = apply_overlays(
            scenario.clone(),
            Some(&overlays),
            Some(&MockRunner::default()),
        )
        .await
        .expect("empty plans should keep scenario unchanged");

        assert_eq!(rewritten, scenario);
    }

    #[tokio::test]
    async fn apply_overlays_start_failure_mentions_overlay_display_name() {
        let scenario = fixture_scenario();
        let mut overlays = fixture_overlays();
        overlays.scopes[0].overlays[0].display_name = "/left".to_string();

        let err = apply_overlays(scenario, Some(&overlays), Some(&StartFailureRunner))
            .await
            .expect_err("startup should fail");

        let message = err.to_string();
        assert!(
            message.contains("failed to start overlay scenario:"),
            "missing startup context: {message}"
        );
        assert!(
            message.contains("/left"),
            "missing overlay display name: {message}"
        );
    }

    #[tokio::test]
    async fn apply_overlays_invalid_json_uses_bounded_body_preview() {
        let hidden = "DO_NOT_LOG_OVERLAY_RESPONSE_TAIL";
        let body = format!(
            "{{{}{}",
            "x".repeat(JSON_EXPORT_RESPONSE_PREVIEW_BYTES + 100),
            hidden
        );
        let runner = RawBodyRunner { body };

        let err = apply_overlays(fixture_scenario(), Some(&fixture_overlays()), Some(&runner))
            .await
            .expect_err("invalid JSON should fail");
        let message = err.to_string();

        assert!(
            matches!(&err, Error::OverlayResponseInvalidJson { .. }),
            "unexpected overlay error: {err:?}"
        );
        assert!(message.contains("body preview:"));
        assert!(message.contains("truncated"));
        assert!(!message.contains(hidden));
    }

    #[tokio::test]
    async fn apply_overlays_valid_json_invalid_shape_does_not_echo_response_body() {
        let hidden = "DO_NOT_LOG_OVERLAY_RESPONSE_VALUE";
        let body = format!(r#"{{"interpositions":"{hidden}"}}"#);
        let runner = RawBodyRunner { body };

        let err = apply_overlays(fixture_scenario(), Some(&fixture_overlays()), Some(&runner))
            .await
            .expect_err("invalid interposition plan shape should fail");
        let message = err.to_string();

        match err {
            Error::OverlayResponseDeserialize { path, .. } => {
                assert_eq!(path, "interpositions");
            }
            other => panic!("unexpected overlay error: {other:?}"),
        }
        assert!(message.contains("did not match interposition plan schema"));
        assert!(!message.contains(hidden));
        assert!(!message.contains("body preview:"));
    }

    #[tokio::test]
    async fn apply_overlays_rewrites_import_binding_chain_for_non_empty_plans() {
        let scenario = fixture_scenario();
        let overlays = fixture_overlays();

        let runner = MockRunner {
            // In fixture_scenario, AttachmentId(0) is the import edge /src.api -> /left.in.
            plans: BTreeMap::from([("overlay_0_0".to_string(), valid_plan(AttachmentId(0)))]),
        };

        let rewritten = apply_overlays(scenario, Some(&overlays), Some(&runner))
            .await
            .expect("non-empty plans should rewrite the binding");

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
    async fn apply_overlays_rewrites_scenario_exports() {
        let scenario = fixture_scenario();
        let overlays = fixture_overlays();

        let runner = MockRunner {
            plans: BTreeMap::from([("overlay_0_0".to_string(), valid_plan(AttachmentId(3)))]),
        };

        let rewritten = apply_overlays(scenario, Some(&overlays), Some(&runner))
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
    async fn apply_overlays_preserves_interposer_config() {
        let mut scenario = fixture_scenario();
        scenario.component_mut(ComponentId(0)).config_schema = Some(serde_json::json!({
            "type": "object",
            "properties": {
                "secret": { "type": "string" },
            },
            "required": ["secret"],
        }));
        scenario.component_mut(ComponentId(1)).config_schema = Some(serde_json::json!({
            "type": "object",
            "properties": {
                "secret": { "type": "string" },
            },
            "required": ["secret"],
        }));
        scenario.component_mut(ComponentId(1)).config = Some(serde_json::json!({
            "secret": "${config.secret}",
        }));
        let overlays = fixture_overlays();

        let runner = MockRunner {
            plans: BTreeMap::from([(
                "overlay_0_0".to_string(),
                InterpositionPlan {
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

        let rewritten = apply_overlays(scenario, Some(&overlays), Some(&runner))
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
    async fn apply_overlays_rejects_interposer_config_slot_interpolation() {
        let scenario = fixture_scenario();
        let overlays = fixture_overlays();

        let runner = MockRunner {
            plans: BTreeMap::from([(
                "overlay_0_0".to_string(),
                InterpositionPlan {
                    interpositions: vec![Interposition {
                        interposer: InterposerComponent {
                            config: Some(serde_json::json!({
                                "upstream": "${slots.in.url}",
                            })),
                            config_schema: Some(serde_json::json!({
                                "type": "object",
                                "properties": {
                                    "upstream": { "type": "string" },
                                },
                                "required": ["upstream"],
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

        let err = apply_overlays(scenario, Some(&overlays), Some(&runner))
            .await
            .expect_err("slot interpolation in generated interposer config must be rejected");

        let Error::InvalidInterpositionPlan { source, .. } = err else {
            panic!("unexpected overlay pass error: {err:?}");
        };
        match *source {
            ValidationError::InvalidInterposerConfig { message } => assert!(
                message.contains("slot interpolation is not allowed"),
                "unexpected error message: {message}"
            ),
            other => panic!("unexpected validation error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_overlays_orders_cross_scope_interposers_by_side_and_depth() {
        let scenario = cross_scope_fixture_scenario();
        let overlays = OverlayPlan {
            scenario: overlays_fixture_scenario(),
            provenance: Default::default(),
            scopes: vec![
                OverlayScopePlan {
                    root_moniker: moniker("/"),
                    overlays: vec![resolved_overlay("root_overlay")],
                },
                OverlayScopePlan {
                    root_moniker: moniker("/right"),
                    overlays: vec![resolved_overlay("right_overlay")],
                },
                OverlayScopePlan {
                    root_moniker: moniker("/left"),
                    overlays: vec![resolved_overlay("left_overlay")],
                },
            ],
        };
        let runner = MockRunner {
            plans: BTreeMap::from([
                // Each scope sees the single binding in its local input as AttachmentId(0).
                ("root_overlay".to_string(), valid_plan(AttachmentId(0))),
                ("right_overlay".to_string(), valid_plan(AttachmentId(0))),
                ("left_overlay".to_string(), valid_plan(AttachmentId(0))),
            ]),
        };

        let rewritten = apply_overlays(scenario, Some(&overlays), Some(&runner))
            .await
            .expect("cross-scope plans should rewrite the binding");

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
    async fn apply_overlays_orders_same_scope_overlays_by_declaration_order() {
        let scenario = fixture_scenario();
        let overlays = OverlayPlan {
            scenario: overlays_fixture_scenario(),
            provenance: Default::default(),
            scopes: vec![OverlayScopePlan {
                root_moniker: moniker("/left"),
                overlays: vec![resolved_overlay("overlay_a"), resolved_overlay("overlay_b")],
            }],
        };
        let runner = MockRunner {
            plans: BTreeMap::from([
                // In fixture_scenario, AttachmentId(0) is the import edge /src.api -> /left.in.
                ("overlay_a".to_string(), valid_plan(AttachmentId(0))),
                ("overlay_b".to_string(), valid_plan(AttachmentId(0))),
            ]),
        };

        let rewritten = apply_overlays(scenario, Some(&overlays), Some(&runner))
            .await
            .expect("same-scope plans should rewrite in declaration order");

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

    fn fixture_overlays() -> OverlayPlan {
        OverlayPlan {
            scenario: overlays_fixture_scenario(),
            provenance: Default::default(),
            scopes: vec![OverlayScopePlan {
                root_moniker: moniker("/left"),
                overlays: vec![resolved_overlay("overlay_0_0")],
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

    fn overlays_fixture_scenario() -> Scenario {
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

    fn valid_plan(target: AttachmentId) -> InterpositionPlan {
        InterpositionPlan {
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

    fn resolved_overlay(name: &str) -> crate::overlays::OverlayExport {
        crate::overlays::OverlayExport {
            export: ExportName::try_from(name).expect("valid export name"),
            display_name: name.to_string(),
        }
    }

    fn moniker(path: &str) -> Moniker {
        Moniker::from(Arc::from(path))
    }
}
