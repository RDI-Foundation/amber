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

pub use document::{ManifestDocError, ParsedManifest};
pub use error::Error;
pub use framework::{
    FrameworkBindingShape, FrameworkCapabilitySpec, framework_capabilities, framework_capability,
};
pub use interpolation::{InterpolatedPart, InterpolatedString, InterpolationSource, ProgramArgs};
pub use manifest::{Manifest, RawManifest};
pub use names::{
    BindingName, ChildName, ExportName, FrameworkCapabilityName, ProvideName, SlotName,
};
pub use refs::{ManifestDigest, ManifestRef, ManifestUrl};
// Keep this available at crate root for internal helpers (spans/document).
pub(crate) use schema::binding_target_key_for_binding;
pub use schema::{
    Binding, BindingSource, BindingSourceRef, BindingTarget, CapabilityDecl, CapabilityKind,
    ComponentDecl, ComponentRef, ConfigSchema, Endpoint, EnvironmentDecl, ExportTarget,
    LocalComponentRef, Network, NetworkProtocol, Program, ProvideDecl, RawBinding, RawExportTarget,
    SlotDecl,
};
pub use spans::{
    BindingSpans, BindingTargetKey, CapabilityDeclSpans, ComponentDeclSpans, EndpointSpans,
    EnvironmentSpans, ExportSpans, ManifestSpans, ProgramSpans, ProvideDeclSpans,
    span_for_json_pointer,
};
