use amber_json5::DiagnosticError;
use miette::Diagnostic;
use semver::Version;
use thiserror::Error;

#[allow(unused_assignments)]
#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum Error {
    #[error("{0}")]
    #[diagnostic(code(manifest::json5_error))]
    Json5(DiagnosticError),

    #[error("{0}")]
    #[diagnostic(code(manifest::deserialize_error))]
    Json5Path(DiagnosticError),

    #[error("io error: {0}")]
    #[diagnostic(code(manifest::io_error))]
    Io(#[from] std::io::Error),

    #[error("invalid manifest reference `{0}`")]
    #[diagnostic(code(manifest::invalid_reference))]
    InvalidManifestRef(String),

    #[error("invalid manifest digest `{0}`")]
    #[diagnostic(code(manifest::invalid_digest))]
    InvalidManifestDigest(String),

    #[error("invalid interpolation `{0}`")]
    #[diagnostic(code(manifest::invalid_interpolation))]
    InvalidInterpolation(String),

    #[error("invalid component ref `{input}`: {message}")]
    #[diagnostic(code(manifest::invalid_component_ref))]
    InvalidComponentRef { input: String, message: String },

    #[error("invalid binding `{input}`: {message}")]
    #[diagnostic(code(manifest::invalid_binding))]
    InvalidBinding { input: String, message: String },

    #[error("binding mixes dot form with `slot`/`capability`")]
    #[diagnostic(
        code(manifest::mixed_binding_form),
        help("Use either dot form or explicit `slot`/`capability` fields.")
    )]
    MixedBindingForm { to: String, from: String },

    #[error("invalid export target `{input}`: {message}")]
    #[diagnostic(code(manifest::invalid_export_target))]
    InvalidExportTarget { input: String, message: String },

    #[error("invalid {kind} name `{name}`: dots are reserved")]
    #[diagnostic(code(manifest::invalid_name))]
    InvalidName { kind: &'static str, name: String },

    #[error("unclosed quote in args string")]
    #[diagnostic(code(manifest::unclosed_quote))]
    UnclosedQuote,

    #[error(
        "program.entrypoint must be non-empty (implicit image entrypoints are unsupported; set \
         `program.entrypoint`/`program.args` to an explicit command)"
    )]
    #[diagnostic(code(manifest::empty_entrypoint))]
    EmptyEntrypoint,

    #[error("export `{export}` references unknown capability `{target}`")]
    #[diagnostic(code(manifest::unknown_export_target))]
    UnknownExportTarget { export: String, target: String },

    #[error("export `{export}` references unknown child `#{child}`")]
    #[diagnostic(code(manifest::unknown_export_child))]
    UnknownExportChild { export: String, child: String },

    #[error("capability `{name}` cannot be declared as both slot and provide")]
    #[diagnostic(code(manifest::ambiguous_capability_name))]
    AmbiguousCapabilityName { name: String },

    #[error("binding target `{to}.{slot}` is bound more than once")]
    #[diagnostic(code(manifest::duplicate_binding_target))]
    DuplicateBindingTarget { to: String, slot: String },

    #[error("binding name `{name}` is used more than once")]
    #[diagnostic(code(manifest::duplicate_binding_name))]
    DuplicateBindingName { name: String },

    #[error("binding references unknown child `#{child}`")]
    #[diagnostic(code(manifest::unknown_binding_child))]
    UnknownBindingChild { child: String },

    #[error("binding target `self.{slot}` references unknown slot")]
    #[diagnostic(code(manifest::unknown_binding_slot))]
    UnknownBindingSlot { slot: String },

    #[error("binding source `self.{capability}` references unknown provide")]
    #[diagnostic(code(manifest::unknown_binding_provide))]
    UnknownBindingProvide { capability: String },

    #[error("unknown framework capability `{capability}`")]
    #[diagnostic(code(manifest::unknown_framework_capability), help("{help}"))]
    UnknownFrameworkCapability { capability: String, help: String },

    #[error("duplicate endpoint name `{name}`")]
    #[diagnostic(code(manifest::duplicate_endpoint_name))]
    DuplicateEndpointName { name: String },

    #[error("unknown endpoint `{name}` referenced")]
    #[diagnostic(code(manifest::unknown_endpoint))]
    UnknownEndpoint { name: String },

    #[error("provide `{name}` must declare an endpoint")]
    #[diagnostic(code(manifest::missing_provide_endpoint))]
    MissingProvideEndpoint { name: String },

    #[error("invalid config definition: {0}")]
    #[diagnostic(code(manifest::invalid_config_schema))]
    InvalidConfigSchema(String),

    #[error("unsupported manifest version `{version}` (supported: {supported_req})")]
    #[diagnostic(code(manifest::unsupported_version))]
    UnsupportedManifestVersion {
        version: Version,
        supported_req: &'static str,
    },

    // --- Environments (resolution environments) ---
    #[error("environment `{name}` extends unknown environment `{extends}`")]
    #[diagnostic(code(manifest::unknown_environment_extends))]
    UnknownEnvironmentExtends { name: String, extends: String },

    #[error("environment `{name}` has a cycle in `extends`")]
    #[diagnostic(code(manifest::environment_cycle))]
    EnvironmentCycle { name: String },

    #[error("component `#{child}` references unknown environment `{environment}`")]
    #[diagnostic(code(manifest::unknown_component_environment))]
    UnknownComponentEnvironment { child: String, environment: String },
}
