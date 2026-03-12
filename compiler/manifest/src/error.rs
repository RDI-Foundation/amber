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

    #[error("invalid program file reference `{path}` at {pointer}: {message}")]
    #[diagnostic(code(manifest::program_file_reference))]
    ProgramFileReference {
        pointer: String,
        path: String,
        message: String,
    },

    #[error("invalid manifest reference `{0}`")]
    #[diagnostic(code(manifest::invalid_reference))]
    InvalidManifestRef(String),

    #[error("invalid manifest digest `{0}`")]
    #[diagnostic(code(manifest::invalid_digest))]
    InvalidManifestDigest(String),

    #[error("invalid interpolation `{0}`")]
    #[diagnostic(code(manifest::invalid_interpolation))]
    InvalidInterpolation(String),

    #[error("invalid `when` path `{input}`: {message}")]
    #[diagnostic(code(manifest::invalid_when_path))]
    InvalidWhenPath { input: String, message: String },

    #[error("invalid `each` path `{input}`: {message}")]
    #[diagnostic(code(manifest::invalid_each_path))]
    InvalidEachPath { input: String, message: String },

    #[error("invalid component ref `{input}`: {message}")]
    #[diagnostic(code(manifest::invalid_component_ref))]
    InvalidComponentRef { input: String, message: String },

    #[error("invalid binding `{input}`: {message}")]
    #[diagnostic(code(manifest::invalid_binding))]
    InvalidBinding { input: String, message: String },

    #[error("invalid mount source `{mount}`: {message}")]
    #[diagnostic(code(manifest::invalid_mount_source))]
    InvalidMountSource { mount: String, message: String },

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

    #[error("unclosed quote in entrypoint string")]
    #[diagnostic(code(manifest::unclosed_quote))]
    UnclosedQuote,

    #[error(
        "program.entrypoint must be non-empty (implicit image entrypoints are unsupported; set \
         `program.entrypoint` to an explicit command)"
    )]
    #[diagnostic(code(manifest::empty_entrypoint))]
    EmptyEntrypoint,

    #[error("program.path must be non-empty")]
    #[diagnostic(code(manifest::empty_program_path))]
    EmptyProgramPath,

    #[error("program.vm.image must be non-empty")]
    #[diagnostic(code(manifest::empty_vm_image))]
    EmptyVmImage,

    #[error("program.vm.cpus must be greater than zero")]
    #[diagnostic(code(manifest::invalid_vm_cpus))]
    InvalidVmCpus,

    #[error("program.vm.memory_mib must be greater than zero")]
    #[diagnostic(code(manifest::invalid_vm_memory_mib))]
    InvalidVmMemoryMib,

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

    #[error("binding references unknown child `#{child}`")]
    #[diagnostic(code(manifest::unknown_binding_child))]
    UnknownBindingChild { child: String },

    #[error("binding target `self.{slot}` is invalid: slots are inputs supplied by the parent")]
    #[diagnostic(
        code(manifest::binding_target_self),
        help(
            "Bind child slots with `to: \"#<child>.<slot>\"`. If the current component needs an \
             internally bound capability, move that program into an explicit child and bind the \
             child slot instead."
        )
    )]
    BindingTargetSelfSlot { slot: String },

    #[error("binding source `self.{capability}` references unknown slot or provide")]
    #[diagnostic(code(manifest::unknown_binding_source))]
    UnknownBindingSource { capability: String },

    #[error("binding source `resources.{resource}` references unknown resource")]
    #[diagnostic(code(manifest::unknown_binding_resource))]
    UnknownBindingResource { resource: String },

    #[error("unknown framework capability `{capability}`")]
    #[diagnostic(code(manifest::unknown_framework_capability), help("{help}"))]
    UnknownFrameworkCapability { capability: String, help: String },

    #[error(
        "framework capability `framework.{capability}` requires experimental feature `{feature}`"
    )]
    #[diagnostic(
        code(manifest::framework_capability_requires_feature),
        help(
            "Add this feature to `experimental_features` in the same manifest, or stop using this \
             framework capability."
        )
    )]
    FrameworkCapabilityRequiresFeature { capability: String, feature: String },

    #[error("duplicate endpoint name `{name}`")]
    #[diagnostic(code(manifest::duplicate_endpoint_name))]
    DuplicateEndpointName { name: String },

    #[error("unknown endpoint `{name}` referenced")]
    #[diagnostic(code(manifest::unknown_endpoint))]
    UnknownEndpoint { name: String },

    #[error("provide `{name}` must declare an endpoint")]
    #[diagnostic(code(manifest::missing_provide_endpoint))]
    MissingProvideEndpoint { name: String },

    #[error("provide `{name}` cannot use capability kind `{kind}`")]
    #[diagnostic(
        code(manifest::unsupported_provide_kind),
        help(
            "Storage is declared in `resources` or received through `slots`, not `provides`. \
             Declare `resources.{name}: {{ kind: \"storage\" }}` and mount it directly, or use \
             `slots.{name}: {{ kind: \"storage\" }}` when the storage is bound from a parent."
        )
    )]
    UnsupportedProvideKind {
        name: String,
        kind: crate::CapabilityKind,
    },

    #[error("duplicate mount name `{name}`")]
    #[diagnostic(code(manifest::duplicate_mount_name))]
    DuplicateMountName { name: String },

    #[error("resource `{name}` cannot use capability kind `{kind}`")]
    #[diagnostic(
        code(manifest::unsupported_resource_kind),
        help("Only `kind: \"storage\"` resources are supported today.")
    )]
    UnsupportedResourceKind {
        name: String,
        kind: crate::CapabilityKind,
    },

    #[error("duplicate mount path `{path}`")]
    #[diagnostic(code(manifest::duplicate_mount_path))]
    DuplicateMountPath { path: String },

    #[error("invalid mount path `{path}`: {message}")]
    #[diagnostic(code(manifest::invalid_mount_path))]
    InvalidMountPath { path: String, message: String },

    #[error("invalid config mount path `{path}`: {message}")]
    #[diagnostic(code(manifest::invalid_mount_config_path))]
    InvalidMountConfigPath { path: String, message: String },

    #[error("invalid secret mount path `{path}`: {message}")]
    #[diagnostic(code(manifest::invalid_mount_secret_path))]
    InvalidMountSecretPath { path: String, message: String },

    #[error("config mount path `{path}` refers to secret config")]
    #[diagnostic(code(manifest::mount_config_path_is_secret))]
    MountConfigPathIsSecret { path: String },

    #[error("secret mount path `{path}` is not secret")]
    #[diagnostic(code(manifest::mount_secret_path_is_not_secret))]
    MountSecretPathIsNotSecret { path: String },

    #[error("mount source `slots.{slot}` references unknown slot")]
    #[diagnostic(code(manifest::unknown_mount_slot))]
    UnknownMountSlot { slot: String },

    #[error("mount source `resources.{resource}` references unknown resource")]
    #[diagnostic(code(manifest::unknown_mount_resource))]
    UnknownMountResource { resource: String },

    #[error("mount source `slots.{slot}` requires a storage slot, but `{slot}` is `{kind}`")]
    #[diagnostic(
        code(manifest::mount_slot_requires_storage),
        help(
            "URL-shaped slots expose fields like `.url`. Storage slots are virtual storage \
             objects and are mounted with `from: \"slots.<slot>\"`."
        )
    )]
    MountSlotRequiresStorage {
        slot: String,
        kind: crate::CapabilityKind,
    },

    #[error("mount source `{mount}` is reserved (not implemented)")]
    #[diagnostic(code(manifest::unsupported_mount_source))]
    UnsupportedMountSource { mount: String },

    #[error("invalid config definition: {0}")]
    #[diagnostic(code(manifest::invalid_config_schema))]
    InvalidConfigSchema(String),

    #[error("unsupported manifest version `{version}` (supported: {supported_req})")]
    #[diagnostic(code(manifest::unsupported_version))]
    UnsupportedManifestVersion {
        version: Version,
        supported_req: &'static str,
    },

    #[error(
        "using {feature} requires manifest_version >= {required_version}, but found \
         {manifest_version}"
    )]
    #[diagnostic(code(manifest::program_syntax_requires_manifest_version))]
    UnsupportedProgramSyntaxForManifestVersion {
        manifest_version: Box<Version>,
        required_version: &'static str,
        feature: &'static str,
        pointer: String,
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
