#![allow(unused_assignments)]

mod config_schema_profile;
mod document;
pub mod framework;
pub mod lint;
mod spans;

mod error;
mod interpolation;
mod manifest;
mod names;
mod refs;
mod schema;
mod slot_query;

pub use document::{ManifestDocError, ParsedManifest};
pub use error::Error;
pub use framework::{
    FrameworkBindingShape, FrameworkCapabilitySpec, framework_capabilities, framework_capability,
};
pub use interpolation::{
    EachPath, InterpolatedPart, InterpolatedString, InterpolationSource, ProgramArgGroup,
    ProgramArgItem, ProgramArgList, ProgramEntrypoint, ProgramEnvValue, RepeatedProgramArg,
    RepeatedProgramArgv, RepeatedProgramEnv, WhenPath,
};
pub use manifest::{ExperimentalFeature, Manifest, RawManifest};
pub use names::{
    ChildName, ExportName, FrameworkCapabilityName, ProvideName, ResourceName, SlotName,
};
pub use refs::{ManifestDigest, ManifestRef, ManifestUrl};
// Keep this available at crate root for internal helpers (spans/document).
pub(crate) use schema::binding_target_key_for_binding;
pub use schema::{
    Binding, BindingSource, BindingSourceRef, BindingTarget, CapabilityDecl, CapabilityKind,
    CapabilityTransport, ComponentDecl, ComponentRef, ConfigSchema, Endpoint, EnvironmentDecl,
    ExportTarget, LocalComponentRef, ManifestBinding, MountSource, Network, NetworkProtocol,
    Program, ProgramCommon, ProgramImage, ProgramMount, ProgramNetworkRef, ProgramPath,
    ProgramVmField, ProvideDecl, RawBinding, RawExportTarget, ResourceDecl, SlotDecl, VmCloudInit,
    VmEgress, VmNetwork, VmProgram, VmScalarU32,
};
pub use slot_query::{
    SlotQuery, SlotQueryError, SlotQueryValidation, SlotTarget, parse_slot_query,
    validate_slot_query_for_slot,
};
pub use spans::{
    BindingSpans, BindingTargetKey, CapabilityDeclSpans, ComponentDeclSpans, EndpointSpans,
    EnvironmentSpans, ExportSpans, ManifestSpans, ProgramSpans, ProvideDeclSpans,
    ResourceDeclSpans, ResourceParamsSpans, span_for_json_pointer,
};
