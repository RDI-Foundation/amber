#![allow(clippy::result_large_err)]

use std::sync::Arc;

use miette::{Diagnostic, LabeledSpan, NamedSource, SourceCode, SourceSpan};
use thiserror::Error;

use crate::{Error as ManifestError, Manifest, ManifestSpans, RawManifest};

#[derive(Clone, Debug)]
pub struct ParsedManifest {
    pub manifest: Manifest,
    pub source: Arc<str>,
    pub spans: Arc<ManifestSpans>,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct ManifestDocError {
    pub kind: ManifestError,
    message: String,
    src: NamedSource<Arc<str>>,
    labels: Vec<LabeledSpan>,
    help: Option<String>,
}

impl ManifestDocError {
    pub fn new(
        name: impl AsRef<str>,
        source: Arc<str>,
        spans: &ManifestSpans,
        kind: ManifestError,
    ) -> Self {
        let src = NamedSource::new(name, Arc::clone(&source)).with_language("json5");
        let message = display_message_for_manifest_error(&kind);
        let labels = labels_for_manifest_error(source.as_ref(), &kind, spans);
        let help = help_for_manifest_error(&kind);
        Self {
            kind,
            message,
            src,
            labels,
            help,
        }
    }
}

impl Diagnostic for ManifestDocError {
    fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        if let ManifestError::Json5Path(de) = &self.kind
            && invalid_when_path_parts(de.detail()).is_some()
        {
            return Some(Box::new("manifest::invalid_when_path"));
        }
        self.kind.code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.kind.severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.help.as_ref().map_or_else(
            || self.kind.help(),
            |help| Some(Box::new(help.as_str()) as Box<dyn std::fmt::Display + 'a>),
        )
    }

    fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.kind.url()
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        Some(&self.src)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        (!self.labels.is_empty()).then(|| Box::new(self.labels.iter().cloned()) as _)
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.kind.diagnostic_source()
    }
}

impl ParsedManifest {
    pub fn parse_named(name: impl AsRef<str>, source: Arc<str>) -> Result<Self, ManifestDocError> {
        let empty_spans = ManifestSpans::default();
        let raw: RawManifest = amber_json5::parse(&source).map_err(|e| {
            let kind = match e.kind() {
                amber_json5::DiagnosticKind::Parse => ManifestError::Json5(e),
                amber_json5::DiagnosticKind::Deserialize => ManifestError::Json5Path(e),
            };
            ManifestDocError::new(name.as_ref(), Arc::clone(&source), &empty_spans, kind)
        })?;

        let spans = Arc::new(ManifestSpans::parse(&source));

        let manifest = raw
            .validate()
            .map_err(|e| ManifestDocError::new(name.as_ref(), Arc::clone(&source), &spans, e))?;

        Ok(Self {
            manifest,
            source,
            spans,
        })
    }
}

fn labels_for_manifest_error(
    source: &str,
    err: &ManifestError,
    spans: &ManifestSpans,
) -> Vec<LabeledSpan> {
    match err {
        ManifestError::Json5(parse) => vec![primary(parse.span(), Some(parse.label().to_string()))],
        ManifestError::Json5Path(de) => {
            vec![primary(de.span(), Some(manifest_json5_path_label(de)))]
        }
        ManifestError::UnsupportedManifestVersion { .. } => vec![primary(
            span_or_default(spans.manifest_version),
            Some("unsupported `manifest_version`".to_string()),
        )],
        ManifestError::UnsupportedProgramSyntaxForManifestVersion { pointer, .. } => {
            let root_span: SourceSpan = (0usize, source.len()).into();
            let span = crate::span_for_json_pointer(source, root_span, pointer)
                .or_else(|| spans.program.as_ref().map(|program| program.whole))
                .or(spans.manifest_version);
            vec![primary(
                span_or_default(span),
                Some("conditional argument group used here".to_string()),
            )]
        }
        ManifestError::InvalidName { kind, name } => labels_for_invalid_name(spans, kind, name),
        ManifestError::MixedBindingForm { to, from } => {
            labels_for_mixed_binding_form(spans, to, from)
        }
        ManifestError::UnknownExportTarget { export, .. }
        | ManifestError::UnknownExportChild { export, .. } => {
            vec![primary(
                span_or_default(spans.exports.get(export.as_str()).map(|s| s.target)),
                Some("export target here".to_string()),
            )]
        }
        ManifestError::AmbiguousCapabilityName { name } => {
            labels_for_ambiguous_capability_name(spans, name)
        }
        ManifestError::DuplicateBindingTarget { to, slot } => {
            labels_for_duplicate_binding_target(spans, to, slot)
        }
        ManifestError::DuplicateBindingName { name } => {
            labels_for_duplicate_binding_name(spans, name)
        }
        ManifestError::BindingTargetSelfSlot { slot } => {
            labels_for_binding_target_self(spans, slot)
        }
        ManifestError::UnknownBindingSource { capability } => {
            labels_for_unknown_binding_source(spans, capability)
        }
        ManifestError::UnknownBindingResource { resource } => {
            labels_for_unknown_binding_resource(spans, resource)
        }
        ManifestError::UnknownBindingChild { child } => {
            labels_for_unknown_binding_child(spans, child)
        }
        ManifestError::UnknownFrameworkCapability { capability, .. }
        | ManifestError::FrameworkCapabilityRequiresFeature { capability, .. } => {
            labels_for_framework_capability_use(spans, capability)
        }
        ManifestError::DuplicateEndpointName { name } => {
            labels_for_duplicate_endpoint_name(spans, name)
        }
        ManifestError::UnknownEndpoint { name } => labels_for_unknown_endpoint(spans, name),
        ManifestError::MissingProvideEndpoint { name } => {
            labels_for_missing_provide_endpoint(spans, name)
        }
        ManifestError::UnsupportedProvideKind { name, .. } => labels_for_provide_kind(spans, name),
        ManifestError::UnsupportedResourceKind { name, .. } => {
            labels_for_resource_decl(spans, name, "unsupported resource kind here")
        }
        ManifestError::DuplicateMountName { name } => {
            labels_for_mount_name(spans, name, "duplicate mount name")
        }
        ManifestError::DuplicateMountPath { path } => {
            labels_for_mount_path(spans, path, "duplicate mount path")
        }
        ManifestError::InvalidMountSource { mount, .. } => {
            labels_for_mount_source(spans, mount, "mount source here")
        }
        ManifestError::InvalidMountPath { path, .. } => {
            labels_for_mount_path(spans, path, "invalid mount path")
        }
        ManifestError::InvalidMountConfigPath { path, .. }
        | ManifestError::MountConfigPathIsSecret { path } => {
            let source = if path.is_empty() {
                "config".to_string()
            } else {
                format!("config.{path}")
            };
            labels_for_mount_source(spans, &source, "mount source here")
        }
        ManifestError::InvalidMountSecretPath { path, .. }
        | ManifestError::MountSecretPathIsNotSecret { path } => {
            let source = format!("secret.{path}");
            labels_for_mount_source(spans, &source, "mount source here")
        }
        ManifestError::UnknownMountSlot { slot }
        | ManifestError::MountSlotRequiresStorage { slot, .. } => {
            labels_for_mount_source(spans, &format!("slots.{slot}"), "mount source here")
        }
        ManifestError::UnknownMountResource { resource } => {
            labels_for_mount_source(spans, &format!("resources.{resource}"), "mount source here")
        }
        ManifestError::UnsupportedMountSource { mount } => {
            labels_for_mount_source(spans, mount, "reserved mount source")
        }
        ManifestError::InvalidConfigSchema(_) => vec![primary(
            span_or_default(spans.config_schema),
            Some("invalid config definition here".to_string()),
        )],
        ManifestError::UnknownEnvironmentExtends { name, .. } => {
            labels_for_unknown_environment_extends(spans, name)
        }
        ManifestError::EnvironmentCycle { name } => labels_for_environment_cycle(spans, name),
        ManifestError::UnknownComponentEnvironment { child, .. } => {
            labels_for_unknown_component_environment(spans, child)
        }
        _ => Vec::new(),
    }
}

fn display_message_for_manifest_error(err: &ManifestError) -> String {
    match err {
        ManifestError::Json5Path(de) => invalid_when_path_parts(de.detail()).map_or_else(
            || err.to_string(),
            |(input, message)| {
                if message == "expected `config.<path>` or `slots.<path>`" {
                    format!(
                        "invalid `when` path `{input}`: `when` must use `config.<path>` or \
                         `slots.<path>`"
                    )
                } else {
                    format!("invalid `when` path `{input}`: {message}")
                }
            },
        ),
        _ => err.to_string(),
    }
}

fn manifest_json5_path_label(de: &amber_json5::DiagnosticError) -> String {
    if let Some((_, message)) = invalid_when_path_parts(de.detail()) {
        if message == "expected `config.<path>` or `slots.<path>`" {
            return "`when` must use `config.<path>` or `slots.<path>`".to_string();
        }

        return "invalid `when` path here".to_string();
    }

    de.label().to_string()
}

fn invalid_when_path_parts(detail: &str) -> Option<(&str, &str)> {
    let detail = detail.strip_prefix("invalid `when` path `")?;
    let (input, message) = detail.split_once("`: ")?;
    Some((input, message))
}

fn help_for_manifest_error(err: &ManifestError) -> Option<String> {
    match err {
        ManifestError::Json5Path(de) => {
            (de.label().starts_with("missing field `manifest_version`"))
                .then(|| "add `manifest_version: \"0.2.0\"` to the root object".to_string())
        }
        ManifestError::UnsupportedProgramSyntaxForManifestVersion {
            required_version,
            feature,
            ..
        } => Some(format!(
            "set `manifest_version` to \"{required_version}\" or remove {feature}"
        )),
        _ => None,
    }
}

fn primary(span: SourceSpan, label: Option<String>) -> LabeledSpan {
    LabeledSpan::new_primary_with_span(label, span)
}

fn span_or_default(span: Option<SourceSpan>) -> SourceSpan {
    span.unwrap_or_else(default_span)
}

fn default_span() -> SourceSpan {
    (0usize, 0usize).into()
}

fn labels_for_mount(
    spans: &ManifestSpans,
    label: &str,
    matches: impl Fn(&crate::spans::ProgramMountSpans) -> bool,
    span: impl Fn(&crate::spans::ProgramMountSpans) -> Option<SourceSpan>,
) -> Vec<LabeledSpan> {
    let Some(program) = spans.program.as_ref() else {
        return Vec::new();
    };
    program
        .mounts
        .iter()
        .filter(|mount| matches(mount))
        .map(|mount| {
            primary(
                span_or_default(span(mount).or(Some(mount.whole))),
                Some(label.to_string()),
            )
        })
        .collect()
}

fn labels_for_duplicate_values(
    matches: &[SourceSpan],
    empty_label: Option<&str>,
    single_label: &str,
    second_label: &str,
    first_label: Option<&str>,
    dedupe_rest_against_second: bool,
) -> Vec<LabeledSpan> {
    match matches {
        [] => empty_label.map_or_else(Vec::new, |label| {
            vec![primary(default_span(), Some(label.to_string()))]
        }),
        [only] => vec![primary(*only, Some(single_label.to_string()))],
        [first, second, rest @ ..] => {
            let mut labels = Vec::new();
            labels.push(primary(*second, Some(second_label.to_string())));
            labels.push(LabeledSpan::new_with_span(
                first_label.map(str::to_string),
                *first,
            ));
            for span in rest {
                if dedupe_rest_against_second && *span == *second {
                    continue;
                }
                labels.push(LabeledSpan::new_with_span(None, *span));
            }
            labels
        }
    }
}

fn labels_for_invalid_name(
    spans: &ManifestSpans,
    kind: &'static str,
    name: &str,
) -> Vec<LabeledSpan> {
    let span =
        match kind {
            "environment" => spans.environments.get(name).map(|s| s.name),
            "child" => spans.components.get(name).map(|s| s.name),
            "slot" => spans.slots.get(name).map(|s| s.name),
            "provide" => spans.provides.get(name).map(|s| s.capability.name),
            "export" => spans.exports.get(name).map(|s| s.name),
            "mount" => {
                return labels_for_mount_name(spans, name, "invalid mount name");
            }
            "binding" => spans.bindings_by_index.iter().find_map(|binding| {
                match binding.name_value.as_deref() {
                    Some(value) if value == name => binding.name.or(Some(binding.whole)),
                    _ => None,
                }
            }),
            _ => None,
        };
    vec![primary(
        span_or_default(span),
        Some("invalid name".to_string()),
    )]
}

fn labels_for_mount_name(spans: &ManifestSpans, name: &str, label: &str) -> Vec<LabeledSpan> {
    labels_for_mount(
        spans,
        label,
        |mount| mount.name_value.as_deref() == Some(name),
        |mount| mount.name,
    )
}

fn labels_for_mount_path(spans: &ManifestSpans, path: &str, label: &str) -> Vec<LabeledSpan> {
    labels_for_mount(
        spans,
        label,
        |mount| mount.path_value.as_deref() == Some(path),
        |mount| mount.path,
    )
}

fn labels_for_mount_source(spans: &ManifestSpans, source: &str, label: &str) -> Vec<LabeledSpan> {
    labels_for_mount(
        spans,
        label,
        |mount| mount.from_value.as_deref() == Some(source),
        |mount| mount.from,
    )
}

fn labels_for_mixed_binding_form(spans: &ManifestSpans, to: &str, from: &str) -> Vec<LabeledSpan> {
    let dot_to = to.contains('.');
    let dot_from = from.contains('.');
    let binding = spans.bindings_by_index.iter().find(|binding| {
        binding.to_value.as_deref() == Some(to) && binding.from_value.as_deref() == Some(from)
    });

    let binding = binding.or_else(|| {
        spans.bindings_by_index.iter().find(|binding| {
            binding.slot_value.is_some()
                && binding.capability_value.is_some()
                && (binding
                    .to_value
                    .as_deref()
                    .is_some_and(|value| value.contains('.'))
                    || binding
                        .from_value
                        .as_deref()
                        .is_some_and(|value| value.contains('.')))
        })
    });

    let Some(binding) = binding else {
        return Vec::new();
    };

    let mut labels = Vec::new();
    if dot_to && let Some(span) = binding.to {
        labels.push(primary(span, Some("dot form here".to_string())));
    }
    if dot_from && let Some(span) = binding.from {
        labels.push(primary(span, Some("dot form here".to_string())));
    }

    if labels.is_empty() {
        labels.push(primary(
            span_or_default(Some(binding.whole)),
            Some("mixed binding form".to_string()),
        ));
    }

    labels
}

fn labels_for_ambiguous_capability_name(spans: &ManifestSpans, name: &str) -> Vec<LabeledSpan> {
    let mut labels = Vec::new();
    if let Some(slot) = spans.slots.get(name) {
        labels.push(primary(
            slot.name,
            Some("declared as a slot here".to_string()),
        ));
    }
    if let Some(provide) = spans.provides.get(name) {
        labels.push(LabeledSpan::new_with_span(
            Some("declared as a provide here".to_string()),
            provide.capability.name,
        ));
    }
    labels
}

fn labels_for_duplicate_binding_target(
    spans: &ManifestSpans,
    to: &str,
    slot: &str,
) -> Vec<LabeledSpan> {
    let Some(key) = crate::binding_target_key_for_binding(to, Some(slot)) else {
        return vec![primary(
            default_span(),
            Some("duplicate binding target".to_string()),
        )];
    };

    let mut matches: Vec<_> = spans
        .bindings_by_index
        .iter()
        .filter(|b| {
            binding_target_key_for_span(b)
                .as_ref()
                .is_some_and(|k| k == &key)
        })
        .map(|b| b.whole)
        .collect();
    if matches.len() < 2 {
        let dot_target = format!("{to}.{slot}");
        let raw_matches: Vec<_> = spans
            .bindings_by_index
            .iter()
            .filter(|b| match (b.to_value.as_deref(), b.slot_value.as_deref()) {
                (Some(to_value), Some(slot_value)) => to_value == to && slot_value == slot,
                (Some(to_value), None) => to_value == dot_target,
                _ => false,
            })
            .map(|b| b.whole)
            .collect();
        if raw_matches.len() > matches.len() {
            matches = raw_matches;
        }
    }

    labels_for_duplicate_values(
        &matches,
        Some("duplicate binding target"),
        "duplicate binding target",
        "second binding here",
        Some("first binding here"),
        false,
    )
}

fn labels_for_duplicate_binding_name(spans: &ManifestSpans, name: &str) -> Vec<LabeledSpan> {
    let matches: Vec<_> = spans
        .bindings_by_index
        .iter()
        .filter_map(|binding| match binding.name_value.as_deref() {
            Some(value) if value == name => binding.name.or(Some(binding.whole)),
            _ => None,
        })
        .collect();

    labels_for_duplicate_values(
        &matches,
        Some("duplicate binding name"),
        "duplicate binding name",
        "second binding name here",
        Some("first binding name here"),
        false,
    )
}

fn binding_span_or_default(
    spans: &ManifestSpans,
    choose: impl FnMut(&crate::BindingSpans) -> Option<SourceSpan>,
) -> SourceSpan {
    spans
        .bindings
        .values()
        .find_map(choose)
        .unwrap_or_else(default_span)
}

fn labels_for_unknown_binding_source(spans: &ManifestSpans, capability: &str) -> Vec<LabeledSpan> {
    let span = binding_span_or_default(spans, |binding| {
        if binding.capability_value.as_deref() == Some(capability) {
            return binding.capability.or(binding.from).or(Some(binding.whole));
        }
        if binding
            .from_value
            .as_deref()
            .and_then(|from| from.strip_prefix("self."))
            .is_some_and(|name| name == capability)
        {
            return binding.from.or(Some(binding.whole));
        }
        None
    });
    vec![primary(
        span,
        Some("unknown slot/provide referenced here".to_string()),
    )]
}

fn labels_for_unknown_binding_resource(spans: &ManifestSpans, resource: &str) -> Vec<LabeledSpan> {
    let span = binding_span_or_default(spans, |binding| {
        if binding.capability_value.as_deref() == Some(resource)
            && binding.from_value.as_deref() == Some("resources")
        {
            return binding.capability.or(binding.from).or(Some(binding.whole));
        }
        if binding
            .from_value
            .as_deref()
            .and_then(|from| from.strip_prefix("resources."))
            .is_some_and(|name| name == resource)
        {
            return binding.from.or(Some(binding.whole));
        }
        None
    });
    vec![primary(
        span,
        Some("unknown resource referenced here".to_string()),
    )]
}

fn labels_for_binding_target_self(spans: &ManifestSpans, slot: &str) -> Vec<LabeledSpan> {
    let span = binding_span_or_default(spans, |binding| {
        if binding.slot_value.as_deref() == Some(slot)
            && binding.to_value.as_deref() == Some("self")
        {
            return binding.slot.or(binding.to).or(Some(binding.whole));
        }
        if binding
            .to_value
            .as_deref()
            .and_then(|to| to.strip_prefix("self."))
            .is_some_and(|name| name == slot)
        {
            return binding.to.or(Some(binding.whole));
        }
        None
    });
    vec![primary(
        span,
        Some("binding targets `self` here".to_string()),
    )]
}

fn labels_for_framework_capability_use(
    spans: &ManifestSpans,
    capability: &str,
) -> Vec<LabeledSpan> {
    let span = binding_span_or_default(spans, |binding| {
        if binding.capability_value.as_deref() == Some(capability)
            && binding.from_value.as_deref() == Some("framework")
        {
            return binding.capability.or(binding.from).or(Some(binding.whole));
        }
        if binding
            .from_value
            .as_deref()
            .and_then(|from| from.strip_prefix("framework."))
            .is_some_and(|name| name == capability)
        {
            return binding.from.or(Some(binding.whole));
        }
        None
    });
    let span = if span == default_span() {
        spans
            .program
            .as_ref()
            .and_then(|program| {
                let expected = format!("framework.{capability}");
                program
                    .mounts
                    .iter()
                    .find(|mount| mount.from_value.as_deref() == Some(expected.as_str()))
                    .and_then(|mount| mount.from.or(Some(mount.whole)))
            })
            .unwrap_or(span)
    } else {
        span
    };
    vec![primary(
        span,
        Some("framework capability referenced here".to_string()),
    )]
}

fn labels_for_unknown_binding_child(spans: &ManifestSpans, child: &str) -> Vec<LabeledSpan> {
    let needle = format!("#{child}");
    let needle_dot = format!("{needle}.");
    let span = binding_span_or_default(spans, |binding| {
        if binding.to_value.as_deref() == Some(needle.as_str())
            || binding
                .to_value
                .as_deref()
                .is_some_and(|to| to.starts_with(&needle_dot))
        {
            return binding.to.or(Some(binding.whole));
        }
        if binding.from_value.as_deref() == Some(needle.as_str())
            || binding
                .from_value
                .as_deref()
                .is_some_and(|from| from.starts_with(&needle_dot))
        {
            return binding.from.or(Some(binding.whole));
        }
        None
    });
    vec![primary(
        span,
        Some("unknown child referenced here".to_string()),
    )]
}

fn labels_for_duplicate_endpoint_name(spans: &ManifestSpans, name: &str) -> Vec<LabeledSpan> {
    let Some(program) = &spans.program else {
        return Vec::new();
    };

    let matches: Vec<_> = program
        .endpoints
        .iter()
        .filter_map(|endpoint| (endpoint.name.as_ref() == name).then_some(endpoint.name_span))
        .collect();

    labels_for_duplicate_values(
        &matches,
        None,
        "duplicate endpoint name",
        "duplicate endpoint name",
        None,
        true,
    )
}

fn labels_for_unknown_endpoint(spans: &ManifestSpans, name: &str) -> Vec<LabeledSpan> {
    let span = spans
        .provides
        .values()
        .find_map(|p| {
            (p.endpoint_value.as_deref() == Some(name))
                .then_some(p.endpoint)
                .flatten()
        })
        .or_else(|| spans.program.as_ref().map(|p| p.whole))
        .unwrap_or_else(default_span);
    vec![primary(
        span,
        Some("unknown endpoint referenced here".to_string()),
    )]
}

fn labels_for_missing_provide_endpoint(spans: &ManifestSpans, name: &str) -> Vec<LabeledSpan> {
    let span = spans
        .provides
        .get(name)
        .map(|p| p.capability.name)
        .unwrap_or_else(default_span);
    vec![primary(
        span,
        Some("missing endpoint for this provide".to_string()),
    )]
}

fn labels_for_provide_kind(spans: &ManifestSpans, name: &str) -> Vec<LabeledSpan> {
    let span = spans
        .provides
        .get(name)
        .and_then(|provide| provide.capability.kind)
        .unwrap_or_else(default_span);
    vec![primary(
        span,
        Some("unsupported provide kind here".to_string()),
    )]
}

fn labels_for_resource_decl(spans: &ManifestSpans, name: &str, label: &str) -> Vec<LabeledSpan> {
    let span = spans
        .resources
        .get(name)
        .and_then(|resource| resource.kind.or(Some(resource.name)))
        .unwrap_or_else(default_span);
    vec![primary(span, Some(label.to_string()))]
}

fn labels_for_unknown_environment_extends(spans: &ManifestSpans, name: &str) -> Vec<LabeledSpan> {
    let span = spans.environments.get(name).and_then(|e| e.extends);
    vec![primary(
        span_or_default(span),
        Some("unknown environment here".to_string()),
    )]
}

fn labels_for_environment_cycle(spans: &ManifestSpans, name: &str) -> Vec<LabeledSpan> {
    let span = spans.environments.get(name).map(|e| e.name);
    vec![primary(
        span_or_default(span),
        Some("cycle originates here".to_string()),
    )]
}

fn labels_for_unknown_component_environment(
    spans: &ManifestSpans,
    child: &str,
) -> Vec<LabeledSpan> {
    let span = spans
        .components
        .get(child)
        .and_then(|c| c.environment.or(Some(c.name)));
    vec![primary(
        span_or_default(span),
        Some("unknown environment referenced here".to_string()),
    )]
}

fn binding_target_key_for_span(span: &crate::BindingSpans) -> Option<crate::BindingTargetKey> {
    let to = span.to_value.as_deref()?;
    crate::binding_target_key_for_binding(to, span.slot_value.as_deref())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use miette::Diagnostic as _;

    use super::*;

    fn labeled_span_text<'a>(source: &'a str, label: &miette::LabeledSpan) -> &'a str {
        let start = label.offset();
        let end = start + label.len();
        source.get(start..end).expect("label span within source")
    }

    #[test]
    fn binding_unknown_field_points_to_key() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          bindings: [
            { to: "#green.llm", form: "#green_router.llm" },
          ],
        }
        "##;

        let err = ParsedManifest::parse_named("test", Arc::from(source)).unwrap_err();
        let labels: Vec<_> = err.labels().unwrap().collect();
        assert_eq!(labels.len(), 1);

        let label = &labels[0];
        let offset = source.find("form").unwrap();
        assert_eq!(label.offset(), offset);
        assert_eq!(label.len(), "form".len());
    }

    #[test]
    fn binding_dot_form_error_points_to_offending_field() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          bindings: [
            { to: "#a.s", from: "#b" },
          ],
        }
        "##;

        let err = ParsedManifest::parse_named("test", Arc::from(source)).unwrap_err();
        let labels: Vec<_> = err.labels().unwrap().collect();
        assert_eq!(labels.len(), 1);

        let label = &labels[0];
        let offset = source.find("\"#b\"").unwrap();
        assert_eq!(label.offset(), offset);
        assert_eq!(label.len(), "\"#b\"".len());
    }

    #[test]
    fn binding_missing_capability_points_to_slot_value() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          components: {
            child: "https://example.com/child",
          },
          bindings: [
            { to: "#child", slot: "s", from: "self" },
          ],
        }
        "##;

        let err = ParsedManifest::parse_named("test", Arc::from(source)).unwrap_err();
        let labels: Vec<_> = err.labels().unwrap().collect();
        assert_eq!(labels.len(), 1);

        let label = &labels[0];
        let offset = source.find("\"s\"").unwrap();
        assert_eq!(label.offset(), offset);
        assert_eq!(label.len(), "\"s\"".len());
    }

    #[test]
    fn binding_missing_slot_points_to_capability_value() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          bindings: [
            { to: "self", from: "self", capability: "c" },
          ],
        }
        "##;

        let err = ParsedManifest::parse_named("test", Arc::from(source)).unwrap_err();
        let labels: Vec<_> = err.labels().unwrap().collect();
        assert_eq!(labels.len(), 1);

        let label = &labels[0];
        let offset = source.find("\"c\"").unwrap();
        assert_eq!(label.offset(), offset);
        assert_eq!(label.len(), "\"c\"".len());
    }

    #[test]
    fn program_unknown_field_points_to_key() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          program: { imag: "x" }
        }
        "##;

        let err = ParsedManifest::parse_named("test", Arc::from(source)).unwrap_err();
        let labels: Vec<_> = err.labels().unwrap().collect();
        assert_eq!(labels.len(), 1);

        let label = &labels[0];
        let offset = source.find("imag").unwrap();
        assert_eq!(label.offset(), offset);
        assert_eq!(label.len(), "imag".len());
    }

    #[test]
    fn json5_missing_close_bracket_points_to_array_open() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          bindings: [
            { to: "self.a", from: "self.b" }
        "##;

        let err = ParsedManifest::parse_named("test", Arc::from(source)).unwrap_err();
        let labels: Vec<_> = err.labels().unwrap().collect();
        assert_eq!(labels.len(), 1);

        let label = &labels[0];
        let offset = source.find('[').unwrap();
        assert_eq!(label.offset(), offset);
    }

    #[test]
    fn json5_missing_close_brace_ignores_comment_and_string() {
        let source = r##"
        {
          // { brace in comment should be ignored
          manifest_version: "0.1.0",
          program: { image: "{not", entrypoint: [] }
        "##;

        let err = ParsedManifest::parse_named("test", Arc::from(source)).unwrap_err();
        let labels: Vec<_> = err.labels().unwrap().collect();
        assert_eq!(labels.len(), 1);

        let label = &labels[0];
        let offset = source.find('{').unwrap();
        assert_eq!(label.offset(), offset);
    }

    #[test]
    fn components_bool_type_error_points_to_value() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          components: true,
        }
        "##;

        let err = ParsedManifest::parse_named("test", Arc::from(source)).unwrap_err();
        assert!(err.to_string().contains("expected object, found boolean"));

        let labels: Vec<_> = err.labels().unwrap().collect();
        assert_eq!(labels.len(), 1);

        let label = &labels[0];
        let offset = source.find("true").unwrap();
        assert_eq!(label.offset(), offset);
        assert_eq!(label.len(), "true".len());
    }

    #[test]
    fn missing_manifest_version_has_fix_suggestion() {
        let source = r#"{ }"#;

        let err = ParsedManifest::parse_named("test", Arc::from(source)).unwrap_err();
        let help = err.help().unwrap().to_string();
        assert!(help.contains("manifest_version"));
        assert!(help.contains("\"0.2.0\""));
    }

    #[test]
    fn manifest_doc_error_unknown_export_target_points_to_target() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: {
            api: { kind: "http", endpoint: "endpoint" },
          },
          exports: { public: "missing" },
        }
        "##;
        let source: Arc<str> = Arc::from(source);
        let err = ParsedManifest::parse_named("<test>", Arc::clone(&source)).unwrap_err();
        assert!(matches!(err.kind, crate::Error::UnknownExportTarget { .. }));

        let labels: Vec<_> = err.labels().expect("labels").collect();
        let has_target = labels
            .iter()
            .any(|label| labeled_span_text(source.as_ref(), label).trim() == "\"missing\"");
        assert!(has_target);
    }

    #[test]
    fn duplicate_binding_target_error_shows_both_sites() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: "https://example.com/a",
            b: "https://example.com/b",
            c: "https://example.com/c",
          },
          bindings: [
            { to: "#a.s", from: "#b.c" },
            { to: "#a.s", from: "#c.d" },
          ],
        }
        "##;

        let err = ParsedManifest::parse_named("test", Arc::from(source)).unwrap_err();
        let labels: Vec<_> = err.labels().unwrap().collect();
        assert!(labels.len() >= 2);

        let starts: Vec<_> = source
            .match_indices("{ to: \"#a.s\"")
            .map(|(idx, _)| idx)
            .collect();
        assert_eq!(starts.len(), 2);
        assert!(labels.iter().any(|l| l.offset() == starts[0]));
        assert!(labels.iter().any(|l| l.offset() == starts[1]));
    }

    #[test]
    fn manifest_doc_error_duplicate_binding_target_marks_second_binding() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "a", port: 80 }, { name: "b", port: 81 }] },
          },
          components: {
            child: "https://example.com/child",
          },
          provides: {
            a: { kind: "http", endpoint: "a" },
            b: { kind: "http", endpoint: "b" },
          },
          bindings: [
            { to: "#child.api", from: "self.a" },
            { to: "#child.api", from: "self.b" },
          ],
        }
        "##;
        let source: Arc<str> = Arc::from(source);
        let err = ParsedManifest::parse_named("<test>", Arc::clone(&source)).unwrap_err();
        assert!(matches!(
            err.kind,
            crate::Error::DuplicateBindingTarget { .. }
        ));

        let labels: Vec<_> = err.labels().expect("labels").collect();
        let second = labels
            .iter()
            .find(|label| label.label() == Some("second binding here"))
            .expect("second binding label");
        let second_text = labeled_span_text(source.as_ref(), second);
        assert!(second_text.contains("self.b"));
    }

    #[test]
    fn manifest_doc_error_duplicate_binding_name_marks_second_binding() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          components: {
            a: "https://example.com/a",
            b: "https://example.com/b",
          },
          bindings: [
            { name: "dup", to: "#a.s", from: "#b.c" },
            { name: "dup", to: "#a.t", from: "#b.d" },
          ],
        }
        "##;
        let source: Arc<str> = Arc::from(source);
        let err = ParsedManifest::parse_named("<test>", Arc::clone(&source)).unwrap_err();
        assert!(matches!(
            err.kind,
            crate::Error::DuplicateBindingName { .. }
        ));

        let labels: Vec<_> = err.labels().expect("labels").collect();
        let second = labels
            .iter()
            .find(|label| label.label() == Some("second binding name here"))
            .expect("second binding name label");
        let starts: Vec<_> = source
            .match_indices("\"dup\"")
            .map(|(idx, _)| idx)
            .collect();
        assert_eq!(starts.len(), 2);
        assert_eq!(second.offset(), starts[1]);
    }

    #[test]
    fn manifest_doc_error_mount_slot_requires_storage_points_to_mount_source() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/var/lib/app", from: "slots.api" },
            ],
          },
          slots: {
            api: { kind: "http" },
          },
        }
        "##;
        let source: Arc<str> = Arc::from(source);
        let err = ParsedManifest::parse_named("<test>", Arc::clone(&source)).unwrap_err();
        assert!(matches!(
            err.kind,
            crate::Error::MountSlotRequiresStorage { .. }
        ));

        let labels: Vec<_> = err.labels().expect("labels").collect();
        let has_mount_source = labels
            .iter()
            .any(|label| labeled_span_text(source.as_ref(), label).contains("\"slots.api\""));
        assert!(has_mount_source);
    }

    #[test]
    fn manifest_doc_error_storage_provide_points_to_kind() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
          },
          provides: {
            state: { kind: "storage", endpoint: "ignored" },
          },
        }
        "##;
        let source: Arc<str> = Arc::from(source);
        let err = ParsedManifest::parse_named("<test>", Arc::clone(&source)).unwrap_err();
        assert!(matches!(
            err.kind,
            crate::Error::UnsupportedProvideKind { .. }
        ));

        let labels: Vec<_> = err.labels().expect("labels").collect();
        let has_storage_kind = labels
            .iter()
            .any(|label| labeled_span_text(source.as_ref(), label).contains("\"storage\""));
        assert!(has_storage_kind);
    }

    #[test]
    fn manifest_doc_error_binding_target_self_points_to_self_target() {
        let source = r##"
        {
          manifest_version: "0.1.0",
          bindings: [
            { to: "self.api", from: "self.api" },
          ],
        }
        "##;
        let source: Arc<str> = Arc::from(source);
        let err = ParsedManifest::parse_named("<test>", Arc::clone(&source)).unwrap_err();
        assert!(matches!(
            err.kind,
            crate::Error::BindingTargetSelfSlot { .. }
        ));

        let labels: Vec<_> = err.labels().expect("labels").collect();
        let has_self_target = labels
            .iter()
            .any(|label| labeled_span_text(source.as_ref(), label).contains("\"self.api\""));
        assert!(has_self_target);
    }
}
