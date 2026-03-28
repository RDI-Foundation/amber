use std::sync::Arc;

use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

#[derive(Clone, Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum ManifestLint {
    #[error("program is never referenced by bindings or exports (in component {component})")]
    #[diagnostic(
        code(manifest::unused_program),
        severity(Warning),
        help(
            "Remove the `program` block if it is not needed, or export/bind one of its provides."
        )
    )]
    UnusedProgram {
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("unused `program`")]
        span: SourceSpan,
    },

    #[error("slot `{name}` is never used (in component {component})")]
    #[diagnostic(
        code(manifest::unused_slot),
        severity(Warning),
        help(
            "Remove the slot `{name}` if it is not needed, or reference it in the program, \
             forward it via a binding, or export it."
        )
    )]
    UnusedSlot {
        name: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("unused slot `{name}`")]
        span: SourceSpan,
    },

    #[error("provide `{name}` is never used or exported (in component {component})")]
    #[diagnostic(
        code(manifest::unused_provide),
        severity(Warning),
        help("Remove the provide `{name}` if it is not needed, or export/bind it.")
    )]
    UnusedProvide {
        name: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("unused provide `{name}`")]
        span: SourceSpan,
    },

    #[error("config property `{path}` is never used (in component {component})")]
    #[diagnostic(
        code(manifest::unused_config),
        severity(Warning),
        help(
            "Remove the config property `{path}` if it is not needed, or reference it via config \
             interpolation."
        )
    )]
    UnusedConfig {
        path: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("unused config property `{path}`")]
        span: SourceSpan,
    },

    #[error("config linting is incomplete (in component {component}): {reason}")]
    #[diagnostic(
        code(manifest::config_lint_incomplete),
        severity(Warning),
        help(
            "Unused config warnings may be incomplete; simplify the config definition or rely on \
             runtime validation."
        )
    )]
    ConfigLintIncomplete {
        component: String,
        reason: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("config definition declared here")]
        span: SourceSpan,
    },

    #[error(
        "command argument references optional config `{path}` without `when` (in component \
         {component})"
    )]
    #[diagnostic(
        code(manifest::optional_command_config),
        severity(Warning),
        help(
            "Wrap the argument in `{{ when: \"config.{path}\", argv: [...] }}` if it should \
             disappear when unset, or make `config.{path}` required."
        )
    )]
    OptionalCommandConfig {
        path: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("unguarded optional config interpolation")]
        span: SourceSpan,
    },

    #[error(
        "environment value references optional config `{path}` without `when` (in component \
         {component})"
    )]
    #[diagnostic(
        code(manifest::optional_env_config),
        severity(Warning),
        help(
            "Wrap the env value in `{{ when: \"config.{path}\", value: ... }}` if it should \
             disappear when unset, or make `config.{path}` required."
        )
    )]
    OptionalEnvConfig {
        path: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("unguarded optional config interpolation")]
        span: SourceSpan,
    },

    #[error("mount references optional config `{path}` without `when` (in component {component})")]
    #[diagnostic(
        code(manifest::optional_mount_config),
        severity(Warning),
        help(
            "Wrap the mount in `{{ when: \"config.{path}\", ... }}` if it should disappear when \
             unset, or make `config.{path}` required."
        )
    )]
    OptionalMountConfig {
        path: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("unguarded optional config interpolation")]
        span: SourceSpan,
    },

    #[error(
        "this `when` condition is unnecessary: slot `{slot}` is required, so it is always bound \
         and this argv item is always included (in component {component})"
    )]
    #[diagnostic(
        code(manifest::required_slot_when),
        severity(Warning),
        help(
            "Remove `when` if this argv item should always be included. If it should disappear \
             when the parent does not bind the slot, mark `slots.{slot}` as `optional: true`."
        )
    )]
    RequiredSlotWhen {
        slot: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("slot is required, so this condition is always true")]
        span: SourceSpan,
    },

    #[error(
        "this `when` condition is unnecessary: slot `{slot}` is required, so it is always bound \
         and this env value is always included (in component {component})"
    )]
    #[diagnostic(
        code(manifest::required_slot_when_env),
        severity(Warning),
        help(
            "Remove `when` if this env value should always be included. If it should disappear \
             when the parent does not bind the slot, mark `slots.{slot}` as `optional: true`."
        )
    )]
    RequiredEnvSlotWhen {
        slot: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("slot is required, so this condition is always true")]
        span: SourceSpan,
    },

    #[error(
        "environment `{environment}` declares resolver `{resolver}` more than once (in component \
         {component})"
    )]
    #[diagnostic(
        code(manifest::duplicate_environment_resolver),
        severity(Warning),
        help("Remove duplicate resolver entries.")
    )]
    DuplicateEnvironmentResolver {
        environment: String,
        resolver: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("duplicate resolver `{resolver}`")]
        span: SourceSpan,
    },

    #[error(
        "binding source `{legacy}` uses deprecated implicit local capability syntax (in component \
         {component})"
    )]
    #[diagnostic(
        code(manifest::deprecated_binding_self_source),
        severity(Warning),
        help("Replace `{legacy}` with `{replacement}`.")
    )]
    DeprecatedBindingSelfSource {
        legacy: String,
        replacement: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("deprecated binding source")]
        span: SourceSpan,
    },

    #[error("export target `{legacy}` uses deprecated `self.*` syntax (in component {component})")]
    #[diagnostic(
        code(manifest::deprecated_export_self_target),
        severity(Warning),
        help("Replace `{legacy}` with `{replacement}`.")
    )]
    DeprecatedExportSelfTarget {
        legacy: String,
        replacement: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("deprecated export target")]
        span: SourceSpan,
    },
}
