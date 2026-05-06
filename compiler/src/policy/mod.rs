use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt,
};

use amber_config as rc;
use amber_manifest::{
    CapabilityDecl, ExperimentalFeature, ProvideDecl, ProvideName, ResourceDecl, ResourceName,
    SlotDecl, SlotName,
};
use amber_scenario::{Component, FrameworkRef, Program, ProvideRef, ResourceRef, SlotRef};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    config::{analysis::ComponentConfigAnalysis, validation},
    linker::program_lowering::validate_lowered_program_mounts,
};

pub type PolicyInput = ScenarioScope;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub scope: PolicyInput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AttachmentId(pub u64);

impl fmt::Display for AttachmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioScope {
    /// Components contained within the governed subtree.
    pub components: Vec<Component>,
    /// Capability flows whose source and target are both within the scope.
    pub bindings: Vec<ScopeBinding>,
    /// Capability flows entering the scope from outside.
    pub imports: Vec<ScopeImport>,
    /// Capability flows leaving the scope.
    pub exports: Vec<ScopeExport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeBinding {
    pub id: AttachmentId,
    pub from: ScopeBindingFrom,
    pub to: SlotRef,
    pub capability: CapabilityDecl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeImport {
    pub id: AttachmentId,
    pub to: SlotRef,
    pub capability: CapabilityDecl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeExport {
    pub id: AttachmentId,
    pub from: ScopeBindingFrom,
    pub capability: CapabilityDecl,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeBindingFrom {
    Component(ProvideRef),
    Resource(ResourceRef),
    Framework(FrameworkRef),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyOutput {
    pub interpositions: Vec<Interposition>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interposition {
    pub interposer: InterposerComponent,
    pub attachments: Vec<Attachment>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    pub target: AttachmentId,
    pub interposer_slot: SlotName,
    pub interposer_provide: ProvideName,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterposerComponent {
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_schema: Option<Value>,
    pub program: Option<Program>,
    #[serde(default)]
    pub slots: BTreeMap<SlotName, SlotDecl>,
    #[serde(default)]
    pub provides: BTreeMap<ProvideName, ProvideDecl>,
    #[serde(default)]
    pub resources: BTreeMap<ResourceName, ResourceDecl>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    #[error("interposition must attach to at least one target")]
    EmptyAttachments,

    #[error("attachment target {target} is referenced more than once")]
    DuplicateAttachmentTarget { target: AttachmentId },

    #[error("interposer slot `{slot}` is attached more than once")]
    DuplicateInterposerSlot { slot: SlotName },

    #[error("attachment target {target} does not exist in the policy input")]
    UnknownAttachmentTarget { target: AttachmentId },

    #[error("attachment references unknown interposer slot `{slot}`")]
    UnknownInterposerSlot { slot: SlotName },

    #[error("attachment references unknown interposer provide `{provide}`")]
    UnknownInterposerProvide { provide: ProvideName },

    #[error("required interposer slot `{slot}` is not attached")]
    UnattachedRequiredInterposerSlot { slot: SlotName },

    #[error(
        "attachment target {target} carries {target_capability}, but interposer slot `{slot}` \
         expects {interposer_capability}"
    )]
    InterposerSlotCapabilityMismatch {
        target: AttachmentId,
        slot: SlotName,
        target_capability: CapabilityDecl,
        interposer_capability: CapabilityDecl,
    },

    #[error(
        "attachment target {target} carries {target_capability}, but interposer provide \
         `{provide}` offers {interposer_capability}"
    )]
    InterposerProvideCapabilityMismatch {
        target: AttachmentId,
        provide: ProvideName,
        target_capability: CapabilityDecl,
        interposer_capability: CapabilityDecl,
    },

    #[error("interposer program is invalid: {message}")]
    InvalidProgram { message: String },

    #[error("interposer must declare a program")]
    MissingInterposerProgram,

    #[error("interposer config requires config_schema")]
    MissingInterposerConfigSchema,

    #[error("interposer config_schema is invalid: {message}")]
    InvalidInterposerConfigSchema { message: String },

    #[error("interposer config is invalid: {message}")]
    InvalidInterposerConfig { message: String },
}

pub fn validate_policy_output(
    output: &PolicyOutput,
    input: &PolicyInput,
    enabled_features: &BTreeSet<ExperimentalFeature>,
) -> Result<(), ValidationError> {
    let parent_template = rc::RootConfigTemplate::Node(rc::ConfigNode::empty_object());
    validate_policy_output_with_config_context(
        output,
        input,
        enabled_features,
        None,
        &parent_template,
    )
}

pub(crate) fn validate_policy_output_for_scope(
    output: &PolicyOutput,
    input: &PolicyInput,
    enabled_features: &BTreeSet<ExperimentalFeature>,
    scope_config: &ComponentConfigAnalysis,
) -> Result<(), ValidationError> {
    validate_policy_output_with_config_context(
        output,
        input,
        enabled_features,
        scope_config.component_schema(),
        scope_config.template(),
    )
}

fn validate_policy_output_with_config_context(
    output: &PolicyOutput,
    input: &PolicyInput,
    enabled_features: &BTreeSet<ExperimentalFeature>,
    parent_schema: Option<&Value>,
    parent_template: &rc::RootConfigTemplate,
) -> Result<(), ValidationError> {
    for interposition in &output.interpositions {
        validate_interposition(
            interposition,
            input,
            enabled_features,
            parent_schema,
            parent_template,
        )?;
    }

    Ok(())
}

fn validate_interposition(
    interposition: &Interposition,
    input: &PolicyInput,
    enabled_features: &BTreeSet<ExperimentalFeature>,
    parent_schema: Option<&Value>,
    parent_template: &rc::RootConfigTemplate,
) -> Result<(), ValidationError> {
    if interposition.attachments.is_empty() {
        return Err(ValidationError::EmptyAttachments);
    }

    validate_interposer_component(
        &interposition.interposer,
        enabled_features,
        parent_schema,
        parent_template,
    )?;

    let mut seen_targets = HashSet::new();
    let mut seen_slots = HashSet::new();

    for attachment in &interposition.attachments {
        if !seen_targets.insert(attachment.target) {
            return Err(ValidationError::DuplicateAttachmentTarget {
                target: attachment.target,
            });
        }
        if !seen_slots.insert(&attachment.interposer_slot) {
            return Err(ValidationError::DuplicateInterposerSlot {
                slot: attachment.interposer_slot.clone(),
            });
        }

        let target_capability = target_capability(input, attachment.target).ok_or(
            ValidationError::UnknownAttachmentTarget {
                target: attachment.target,
            },
        )?;

        let slot_decl = interposition
            .interposer
            .slots
            .get(&attachment.interposer_slot)
            .ok_or_else(|| ValidationError::UnknownInterposerSlot {
                slot: attachment.interposer_slot.clone(),
            })?;
        if slot_decl.decl != *target_capability {
            return Err(ValidationError::InterposerSlotCapabilityMismatch {
                target: attachment.target,
                slot: attachment.interposer_slot.clone(),
                target_capability: target_capability.clone(),
                interposer_capability: slot_decl.decl.clone(),
            });
        }

        let provide_decl = interposition
            .interposer
            .provides
            .get(&attachment.interposer_provide)
            .ok_or_else(|| ValidationError::UnknownInterposerProvide {
                provide: attachment.interposer_provide.clone(),
            })?;
        if provide_decl.decl != *target_capability {
            return Err(ValidationError::InterposerProvideCapabilityMismatch {
                target: attachment.target,
                provide: attachment.interposer_provide.clone(),
                target_capability: target_capability.clone(),
                interposer_capability: provide_decl.decl.clone(),
            });
        }
    }

    for (slot, decl) in &interposition.interposer.slots {
        if !decl.optional && !seen_slots.contains(slot) {
            return Err(ValidationError::UnattachedRequiredInterposerSlot { slot: slot.clone() });
        }
    }

    Ok(())
}

fn validate_interposer_component(
    component: &InterposerComponent,
    enabled_features: &BTreeSet<ExperimentalFeature>,
    parent_schema: Option<&Value>,
    parent_template: &rc::RootConfigTemplate,
) -> Result<(), ValidationError> {
    if component.config.is_some() && component.config_schema.is_none() {
        return Err(ValidationError::MissingInterposerConfigSchema);
    }
    if let Some(schema) = component.config_schema.as_ref() {
        rc::validate_config_schema(schema).map_err(|err| {
            ValidationError::InvalidInterposerConfigSchema {
                message: err.to_string(),
            }
        })?;
        let composed = validation::compose_component_config_template(
            component.config.as_ref(),
            parent_schema,
            parent_template,
            schema,
        )
        .map_err(|message| ValidationError::InvalidInterposerConfig { message })?;
        if let Some(err) = validation::validate_composed_component_config(schema, &composed)
            .into_iter()
            .next()
        {
            return Err(ValidationError::InvalidInterposerConfig {
                message: err.message,
            });
        }
    }

    let Some(program) = component.program.as_ref() else {
        return Err(ValidationError::MissingInterposerProgram);
    };

    let mount_source_indices = (0..program.mounts().len()).collect::<Vec<_>>();
    validate_lowered_program_mounts(
        program,
        &mount_source_indices,
        None,
        &component.resources,
        &component.slots,
        enabled_features,
    )
    .map_err(|errors| ValidationError::InvalidProgram {
        message: errors
            .into_iter()
            .next()
            .expect("program validation returned at least one error")
            .message,
    })
}

fn target_capability(input: &PolicyInput, target: AttachmentId) -> Option<&CapabilityDecl> {
    input
        .bindings
        .iter()
        .find(|binding| binding.id == target)
        .map(|binding| &binding.capability)
        .or_else(|| {
            input
                .imports
                .iter()
                .find(|import| import.id == target)
                .map(|import| &import.capability)
        })
        .or_else(|| {
            input
                .exports
                .iter()
                .find(|export| export.id == target)
                .map(|export| &export.capability)
        })
}

#[cfg(test)]
mod tests {
    use amber_manifest::CapabilityKind;
    use amber_scenario::{ProgramCommon, ProgramMount, ProgramPath};
    use serde_json::json;

    use super::*;
    use crate::config::analysis::ComponentConfigAnalysis;

    fn http_capability() -> CapabilityDecl {
        CapabilityDecl::builder().kind(CapabilityKind::Http).build()
    }

    fn http_slot(optional: bool) -> SlotDecl {
        SlotDecl::builder()
            .decl(http_capability())
            .optional(optional)
            .build()
    }

    fn http_provide() -> ProvideDecl {
        ProvideDecl::builder().decl(http_capability()).build()
    }

    fn storage_slot(optional: bool) -> SlotDecl {
        SlotDecl::builder()
            .decl(
                CapabilityDecl::builder()
                    .kind(CapabilityKind::Storage)
                    .build(),
            )
            .optional(optional)
            .build()
    }

    fn scope_with_binding(capability: CapabilityDecl) -> ScenarioScope {
        ScenarioScope {
            components: Vec::new(),
            bindings: vec![ScopeBinding {
                id: AttachmentId(1),
                from: ScopeBindingFrom::Component(ProvideRef {
                    component: amber_scenario::ComponentId(0),
                    name: "external".to_string(),
                }),
                to: SlotRef {
                    component: amber_scenario::ComponentId(1),
                    name: "target".to_string(),
                },
                capability,
            }],
            imports: Vec::new(),
            exports: Vec::new(),
        }
    }

    fn valid_output() -> PolicyOutput {
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
                    slots: BTreeMap::from([(SlotName::try_from("in").unwrap(), http_slot(false))]),
                    provides: BTreeMap::from([(
                        ProvideName::try_from("out").unwrap(),
                        http_provide(),
                    )]),
                    resources: BTreeMap::new(),
                    metadata: None,
                },
                attachments: vec![Attachment {
                    target: AttachmentId(1),
                    interposer_slot: SlotName::try_from("in").unwrap(),
                    interposer_provide: ProvideName::try_from("out").unwrap(),
                }],
            }],
        }
    }

    #[test]
    fn validation_accepts_valid_interposition() {
        let output = valid_output();
        let scope = scope_with_binding(http_capability());

        validate_policy_output(&output, &scope, &BTreeSet::new()).expect("output should validate");
    }

    #[test]
    fn validation_rejects_duplicate_attachment_target() {
        let mut output = valid_output();
        output.interpositions[0].attachments.push(Attachment {
            target: AttachmentId(1),
            interposer_slot: SlotName::try_from("other").unwrap(),
            interposer_provide: ProvideName::try_from("out").unwrap(),
        });
        output.interpositions[0]
            .interposer
            .slots
            .insert(SlotName::try_from("other").unwrap(), http_slot(true));

        let err = validate_policy_output(
            &output,
            &scope_with_binding(http_capability()),
            &BTreeSet::new(),
        )
        .expect_err("duplicate target must be rejected");
        assert_eq!(
            err,
            ValidationError::DuplicateAttachmentTarget {
                target: AttachmentId(1)
            }
        );
    }

    #[test]
    fn validation_rejects_duplicate_input_slot() {
        let mut output = valid_output();
        output.interpositions[0].attachments.push(Attachment {
            target: AttachmentId(2),
            interposer_slot: SlotName::try_from("in").unwrap(),
            interposer_provide: ProvideName::try_from("out").unwrap(),
        });
        let mut scope = scope_with_binding(http_capability());
        scope.imports.push(ScopeImport {
            id: AttachmentId(2),
            to: SlotRef {
                component: amber_scenario::ComponentId(1),
                name: "import".to_string(),
            },
            capability: http_capability(),
        });

        let err = validate_policy_output(&output, &scope, &BTreeSet::new())
            .expect_err("duplicate input slot must be rejected");
        assert_eq!(
            err,
            ValidationError::DuplicateInterposerSlot {
                slot: SlotName::try_from("in").unwrap()
            }
        );
    }

    #[test]
    fn validation_rejects_missing_required_slot_attachment() {
        let mut output = valid_output();
        output.interpositions[0]
            .interposer
            .slots
            .insert(SlotName::try_from("aux").unwrap(), http_slot(false));

        let err = validate_policy_output(
            &output,
            &scope_with_binding(http_capability()),
            &BTreeSet::new(),
        )
        .expect_err("missing required slot must be rejected");
        assert_eq!(
            err,
            ValidationError::UnattachedRequiredInterposerSlot {
                slot: SlotName::try_from("aux").unwrap()
            }
        );
    }

    #[test]
    fn validation_rejects_capability_mismatch() {
        let mut output = valid_output();
        output.interpositions[0]
            .interposer
            .slots
            .insert(SlotName::try_from("in").unwrap(), storage_slot(false));

        let err = validate_policy_output(
            &output,
            &scope_with_binding(http_capability()),
            &BTreeSet::new(),
        )
        .expect_err("slot capability mismatch must be rejected");
        assert!(matches!(
            err,
            ValidationError::InterposerSlotCapabilityMismatch {
                target: AttachmentId(1),
                ..
            }
        ));
    }

    #[test]
    fn validation_rejects_invalid_program_mounts() {
        let mut output = valid_output();
        output.interpositions[0].interposer.program = Some(Program::Path(ProgramPath {
            path: "./interposer".to_string(),
            args: amber_manifest::ProgramEntrypoint::default(),
            common: ProgramCommon {
                env: BTreeMap::new(),
                network: None,
                mounts: vec![ProgramMount::Resource {
                    path: "/data".to_string(),
                    resource: "missing".to_string(),
                }],
            },
        }));

        let err = validate_policy_output(
            &output,
            &scope_with_binding(http_capability()),
            &BTreeSet::new(),
        )
        .expect_err("invalid program mount must be rejected");
        assert!(matches!(err, ValidationError::InvalidProgram { .. }));
    }

    #[test]
    fn validation_rejects_missing_interposer_program() {
        let mut output = valid_output();
        output.interpositions[0].interposer.program = None;

        let err = validate_policy_output(
            &output,
            &scope_with_binding(http_capability()),
            &BTreeSet::new(),
        )
        .expect_err("missing interposer program must be rejected");
        assert_eq!(err, ValidationError::MissingInterposerProgram);
    }

    #[test]
    fn validation_rejects_interposer_config_without_schema() {
        let mut output = valid_output();
        output.interpositions[0].interposer.config = Some(serde_json::json!({
            "secret": "${config.secret}",
        }));

        let err = validate_policy_output(
            &output,
            &scope_with_binding(http_capability()),
            &BTreeSet::new(),
        )
        .expect_err("interposer config without schema must be rejected");

        assert_eq!(err, ValidationError::MissingInterposerConfigSchema);
    }

    #[test]
    fn validation_rejects_interposer_config_that_does_not_match_schema() {
        let mut output = valid_output();
        output.interpositions[0].interposer.config = Some(serde_json::json!({
            "redaction_terms": "not an array",
        }));
        output.interpositions[0].interposer.config_schema = Some(serde_json::json!({
            "type": "object",
            "properties": {
                "redaction_terms": {
                    "type": "array",
                    "items": { "type": "string" },
                },
            },
            "required": ["redaction_terms"],
        }));

        let err = validate_policy_output(
            &output,
            &scope_with_binding(http_capability()),
            &BTreeSet::new(),
        )
        .expect_err("invalid interposer config must be rejected");

        assert!(matches!(
            err,
            ValidationError::InvalidInterposerConfig { .. }
        ));
    }

    #[test]
    fn validation_rejects_interposer_config_slot_interpolation() {
        let mut output = valid_output();
        output.interpositions[0].interposer.config = Some(serde_json::json!({
            "upstream": "${slots.in.url}",
        }));
        output.interpositions[0].interposer.config_schema = Some(serde_json::json!({
            "type": "object",
            "properties": {
                "upstream": { "type": "string" },
            },
            "required": ["upstream"],
        }));

        let err = validate_policy_output(
            &output,
            &scope_with_binding(http_capability()),
            &BTreeSet::new(),
        )
        .expect_err("slot interpolation in interposer config must be rejected");

        match err {
            ValidationError::InvalidInterposerConfig { message } => assert!(
                message.contains("slot interpolation is not allowed"),
                "unexpected error message: {message}"
            ),
            other => panic!("unexpected validation error: {other:?}"),
        }
    }

    #[test]
    fn validation_rejects_missing_required_interposer_config_without_defaults() {
        let mut output = valid_output();
        output.interpositions[0].interposer.config_schema = Some(serde_json::json!({
            "type": "object",
            "properties": {
                "token": { "type": "string" },
            },
            "required": ["token"],
        }));

        let err = validate_policy_output(
            &output,
            &scope_with_binding(http_capability()),
            &BTreeSet::new(),
        )
        .expect_err("missing required interposer config must be rejected");

        match err {
            ValidationError::InvalidInterposerConfig { message } => assert!(
                message.contains("missing required field config.token"),
                "unexpected error message: {message}"
            ),
            other => panic!("unexpected validation error: {other:?}"),
        }
    }

    #[test]
    fn validation_accepts_interposer_config_references_to_scope_config() {
        let mut output = valid_output();
        output.interpositions[0].interposer.config = Some(serde_json::json!({
            "redaction_terms": ["${config.secret}"],
            "snapshot": "${config.settings}",
        }));
        output.interpositions[0].interposer.config_schema = Some(serde_json::json!({
            "type": "object",
            "properties": {
                "redaction_terms": {
                    "type": "array",
                    "items": { "type": "string" },
                },
                "snapshot": {
                    "type": "object",
                    "properties": {
                        "mode": { "type": "string" },
                    },
                    "required": ["mode"],
                },
            },
            "required": ["redaction_terms", "snapshot"],
        }));
        let parent_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "secret": { "type": "string" },
                "settings": {
                    "type": "object",
                    "properties": {
                        "mode": { "type": "string" },
                    },
                    "required": ["mode"],
                },
            },
            "required": ["secret", "settings"],
        });
        let scope_config = ComponentConfigAnalysis::standalone(
            None,
            Some(parent_schema.clone()),
            Some(parent_schema),
        )
        .expect("scope config analysis");

        validate_policy_output_for_scope(
            &output,
            &scope_with_binding(http_capability()),
            &BTreeSet::new(),
            &scope_config,
        )
        .expect("scope config references should validate as normal config templates");
    }

    #[test]
    fn policy_output_deserialize_defaults_omitted_collections() {
        let output: PolicyOutput = serde_json::from_value(json!({
            "interpositions": [{
                "interposer": {
                    "program": {
                        "path": "/usr/bin/env",
                        "args": ["python3"],
                    },
                    "slots": {
                        "in": { "kind": "http" }
                    },
                    "provides": {
                        "out": { "kind": "http" }
                    }
                },
                "attachments": [{
                    "target": 1,
                    "interposer_slot": "in",
                    "interposer_provide": "out"
                }]
            }]
        }))
        .expect("policy output should deserialize");

        assert!(output.interpositions[0].interposer.resources.is_empty());
    }

    #[test]
    fn policy_output_deserialize_accepts_explicit_noop() {
        let output: PolicyOutput = serde_json::from_value(json!({
            "interpositions": []
        }))
        .expect("explicit empty interpositions should deserialize");

        validate_policy_output(
            &output,
            &ScenarioScope {
                components: Vec::new(),
                bindings: Vec::new(),
                imports: Vec::new(),
                exports: Vec::new(),
            },
            &BTreeSet::new(),
        )
        .expect("explicit no-op output should validate");
    }

    #[test]
    fn policy_output_deserialize_rejects_missing_interpositions() {
        let err = serde_json::from_value::<PolicyOutput>(json!({}))
            .expect_err("top-level interpositions field must be required");

        assert!(
            err.to_string().contains("missing field `interpositions`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn policy_output_deserialize_rejects_misspelled_interpositions() {
        let err = serde_json::from_value::<PolicyOutput>(json!({
            "interposition": []
        }))
        .expect_err("misspelled top-level field must be rejected");

        assert!(
            err.to_string().contains("unknown field `interposition`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn policy_output_deserialize_rejects_missing_attachments() {
        let err = serde_json::from_value::<PolicyOutput>(json!({
            "interpositions": [{
                "interposer": {
                    "program": {
                        "path": "/usr/bin/env",
                        "args": ["python3"],
                    },
                },
            }]
        }))
        .expect_err("interposition attachments field must be required");

        assert!(
            err.to_string().contains("missing field `attachments`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn policy_output_deserialize_rejects_unknown_nested_fields() {
        let err = serde_json::from_value::<PolicyOutput>(json!({
            "interpositions": [{
                "interposer": {
                    "program": {
                        "path": "/usr/bin/env",
                        "args": ["python3"],
                    },
                    "slots": {
                        "in": { "kind": "http" }
                    },
                    "provides": {
                        "out": { "kind": "http" }
                    },
                    "unexpected": true,
                },
                "attachments": [{
                    "target": 1,
                    "interposer_slot": "in",
                    "interposer_provide": "out"
                }]
            }]
        }))
        .expect_err("unknown nested fields must be rejected");

        assert!(
            err.to_string().contains("unknown field `unexpected`"),
            "unexpected error: {err}"
        );
    }
}
