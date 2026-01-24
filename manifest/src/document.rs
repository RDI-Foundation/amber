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
        let message = kind.to_string();
        let labels = labels_for_manifest_error(&kind, spans);
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

fn labels_for_manifest_error(err: &ManifestError, spans: &ManifestSpans) -> Vec<LabeledSpan> {
    match err {
        ManifestError::Json5(parse) => vec![primary(parse.span(), Some(parse.label().to_string()))],
        ManifestError::Json5Path(de) => vec![primary(de.span(), Some(de.label().to_string()))],
        ManifestError::UnsupportedManifestVersion { .. } => vec![primary(
            span_or_default(spans.manifest_version),
            Some("unsupported `manifest_version`".to_string()),
        )],
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
        ManifestError::SelfBinding {
            to,
            slot,
            from,
            capability,
            name,
        } => labels_for_self_binding(spans, to, slot, from, capability, name.as_deref()),
        ManifestError::UnknownBindingSlot { slot } => labels_for_unknown_binding_slot(spans, slot),
        ManifestError::UnknownBindingProvide { capability } => {
            labels_for_unknown_binding_provide(spans, capability)
        }
        ManifestError::UnknownBindingChild { child } => {
            labels_for_unknown_binding_child(spans, child)
        }
        ManifestError::UnknownFrameworkCapability { capability, .. } => {
            labels_for_unknown_framework_capability(spans, capability)
        }
        ManifestError::DuplicateEndpointName { name } => {
            labels_for_duplicate_endpoint_name(spans, name)
        }
        ManifestError::UnknownEndpoint { name } => labels_for_unknown_endpoint(spans, name),
        ManifestError::MissingProvideEndpoint { name } => {
            labels_for_missing_provide_endpoint(spans, name)
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

fn help_for_manifest_error(err: &ManifestError) -> Option<String> {
    match err {
        ManifestError::Json5Path(de) => {
            (de.label().starts_with("missing field `manifest_version`"))
                .then(|| "add `manifest_version: \"0.1.0\"` to the root object".to_string())
        }
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

    let matches: Vec<_> = spans
        .bindings_by_index
        .iter()
        .filter(|b| {
            binding_target_key_for_span(b)
                .as_ref()
                .is_some_and(|k| k == &key)
        })
        .map(|b| b.whole)
        .collect();

    match matches.as_slice() {
        [] => vec![primary(
            default_span(),
            Some("duplicate binding target".to_string()),
        )],
        [only] => vec![primary(*only, Some("duplicate binding target".to_string()))],
        [first, second, rest @ ..] => {
            let mut labels = Vec::new();
            labels.push(primary(*second, Some("second binding here".to_string())));
            labels.push(LabeledSpan::new_with_span(
                Some("first binding here".to_string()),
                *first,
            ));
            for span in rest {
                labels.push(LabeledSpan::new_with_span(None, *span));
            }
            labels
        }
    }
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

    match matches.as_slice() {
        [] => vec![primary(
            default_span(),
            Some("duplicate binding name".to_string()),
        )],
        [only] => vec![primary(*only, Some("duplicate binding name".to_string()))],
        [first, second, rest @ ..] => {
            let mut labels = Vec::new();
            labels.push(primary(
                *second,
                Some("second binding name here".to_string()),
            ));
            labels.push(LabeledSpan::new_with_span(
                Some("first binding name here".to_string()),
                *first,
            ));
            for span in rest {
                labels.push(LabeledSpan::new_with_span(None, *span));
            }
            labels
        }
    }
}

fn labels_for_self_binding(
    spans: &ManifestSpans,
    to: &str,
    slot: &str,
    from: &str,
    capability: &str,
    name: Option<&str>,
) -> Vec<LabeledSpan> {
    let Some(key) = crate::binding_target_key_for_binding(to, Some(slot)) else {
        return vec![primary(
            default_span(),
            Some("self-binding here".to_string()),
        )];
    };

    let binding = spans.bindings_by_index.iter().find(|b| {
        if !binding_name_matches(b, name) {
            return false;
        }
        let target_match = binding_target_key_for_span(b)
            .as_ref()
            .is_some_and(|k| k == &key);
        if !target_match {
            return false;
        }
        binding_source_parts_for_span(b).is_some_and(|(span_from, span_capability)| {
            span_from == from && span_capability == capability
        })
    });

    let Some(binding) = binding else {
        return vec![primary(
            default_span(),
            Some("self-binding here".to_string()),
        )];
    };

    vec![primary(
        span_or_default(Some(binding.whole)),
        Some("self-binding here".to_string()),
    )]
}

fn binding_name_matches(binding: &crate::BindingSpans, name: Option<&str>) -> bool {
    match name {
        Some(expected) => binding.name_value.as_deref() == Some(expected),
        None => binding.name_value.is_none(),
    }
}

fn binding_source_parts_for_span(span: &crate::BindingSpans) -> Option<(String, String)> {
    if let (Some(from), Some(capability)) =
        (span.from_value.as_deref(), span.capability_value.as_deref())
    {
        let source = crate::parse_binding_source_ref(from).ok()?;
        return Some((source.to_string(), capability.to_string()));
    }

    let from = span.from_value.as_deref()?;
    let (source, capability) = crate::split_binding_source(from).ok()?;
    Some((source.to_string(), capability))
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

fn labels_for_unknown_binding_slot(spans: &ManifestSpans, slot: &str) -> Vec<LabeledSpan> {
    let span = binding_span_or_default(spans, |binding| {
        (binding.slot_value.as_deref() == Some(slot))
            .then_some(binding.slot.or(binding.to).or(Some(binding.whole)))
            .flatten()
    });
    vec![primary(
        span,
        Some("unknown slot referenced here".to_string()),
    )]
}

fn labels_for_unknown_binding_provide(spans: &ManifestSpans, capability: &str) -> Vec<LabeledSpan> {
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
        Some("unknown provide referenced here".to_string()),
    )]
}

fn labels_for_unknown_framework_capability(
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
    vec![primary(
        span,
        Some("unknown framework capability referenced here".to_string()),
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

    match matches.as_slice() {
        [] => Vec::new(),
        [only] => vec![primary(*only, Some("duplicate endpoint name".to_string()))],
        [first, second, rest @ ..] => {
            let mut labels = Vec::new();
            labels.push(primary(
                *second,
                Some("duplicate endpoint name".to_string()),
            ));
            labels.push(LabeledSpan::new_with_span(None, *first));
            for span in rest {
                if *span == *second {
                    continue;
                }
                labels.push(LabeledSpan::new_with_span(None, *span));
            }
            labels
        }
    }
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
