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
            spans.manifest_version.unwrap_or((0usize, 0usize).into()),
            Some("unsupported `manifest_version`".to_string()),
        )],
        ManifestError::InvalidName { kind, name } => {
            let span = match *kind {
                "environment" => spans.environments.get(name.as_str()).map(|s| s.name),
                "child" => spans.components.get(name.as_str()).map(|s| s.name),
                "slot" => spans.slots.get(name.as_str()).map(|s| s.name),
                "provide" => spans.provides.get(name.as_str()).map(|s| s.capability.name),
                "export" => spans.exports.get(name.as_str()).map(|s| s.name),
                _ => None,
            };
            vec![primary(
                span.unwrap_or((0usize, 0usize).into()),
                Some("invalid name".to_string()),
            )]
        }
        ManifestError::UnknownExportTarget { export, .. }
        | ManifestError::UnknownExportChild { export, .. } => {
            let span = spans
                .exports
                .get(export.as_str())
                .map(|s| s.target)
                .unwrap_or((0usize, 0usize).into());
            vec![primary(span, Some("export target here".to_string()))]
        }
        ManifestError::AmbiguousCapabilityName { name } => {
            let mut labels = Vec::new();
            if let Some(slot) = spans.slots.get(name.as_str()) {
                labels.push(primary(
                    slot.name,
                    Some("declared as a slot here".to_string()),
                ));
            }
            if let Some(provide) = spans.provides.get(name.as_str()) {
                labels.push(LabeledSpan::new_with_span(
                    Some("declared as a provide here".to_string()),
                    provide.capability.name,
                ));
            }
            labels
        }
        ManifestError::DuplicateBindingTarget { to, slot } => {
            let Some(key) = crate::binding_target_key_for_binding(to, Some(slot.as_str())) else {
                return vec![primary(
                    (0usize, 0usize).into(),
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

            if matches.is_empty() {
                return vec![primary(
                    (0usize, 0usize).into(),
                    Some("duplicate binding target".to_string()),
                )];
            }

            if matches.len() == 1 {
                return vec![primary(
                    matches[0],
                    Some("duplicate binding target".to_string()),
                )];
            }

            let mut labels = Vec::new();
            labels.push(primary(matches[1], Some("second binding here".to_string())));
            labels.push(LabeledSpan::new_with_span(
                Some("first binding here".to_string()),
                matches[0],
            ));
            for &s in &matches[2..] {
                labels.push(LabeledSpan::new_with_span(None, s));
            }
            labels
        }
        ManifestError::UnknownBindingSlot { slot } => {
            let needle = slot.as_str();
            let label = Some("unknown slot referenced here".to_string());
            let span = spans
                .bindings
                .values()
                .find_map(|b| {
                    (b.slot_value.as_deref() == Some(needle))
                        .then_some(b.slot.or(b.to).or(Some(b.whole)))
                        .flatten()
                })
                .unwrap_or((0usize, 0usize).into());
            vec![primary(span, label)]
        }
        ManifestError::UnknownBindingProvide { capability } => {
            let needle = capability.as_str();
            let label = Some("unknown provide referenced here".to_string());
            let span = spans
                .bindings
                .values()
                .find_map(|b| {
                    if b.capability_value.as_deref() == Some(needle) {
                        return b.capability.or(b.from).or(Some(b.whole));
                    }
                    if b.from_value
                        .as_deref()
                        .and_then(|from| from.strip_prefix("self."))
                        .is_some_and(|name| name == needle)
                    {
                        return b.from.or(Some(b.whole));
                    }
                    None
                })
                .unwrap_or((0usize, 0usize).into());
            vec![primary(span, label)]
        }
        ManifestError::UnknownBindingChild { child } => {
            let needle = format!("#{child}");
            let needle_dot = format!("{needle}.");
            let span = spans
                .bindings
                .values()
                .find_map(|b| {
                    if b.to_value.as_deref() == Some(needle.as_str())
                        || b.to_value
                            .as_deref()
                            .is_some_and(|to| to.starts_with(&needle_dot))
                    {
                        return b.to.or(Some(b.whole));
                    }
                    if b.from_value.as_deref() == Some(needle.as_str())
                        || b.from_value
                            .as_deref()
                            .is_some_and(|from| from.starts_with(&needle_dot))
                    {
                        return b.from.or(Some(b.whole));
                    }
                    None
                })
                .unwrap_or((0usize, 0usize).into());
            vec![primary(
                span,
                Some("unknown child referenced here".to_string()),
            )]
        }
        ManifestError::DuplicateEndpointName { name } => {
            let Some(program) = &spans.program else {
                return Vec::new();
            };

            let matches: Vec<_> = program
                .endpoints
                .iter()
                .filter_map(|(n, s)| (n.as_ref() == name).then_some(*s))
                .collect();

            if matches.is_empty() {
                return Vec::new();
            }

            let mut labels = Vec::new();
            let (primary_span, rest) = matches
                .get(1)
                .copied()
                .map(|s| (s, &matches[..]))
                .unwrap_or((matches[0], &matches[..]));
            labels.push(primary(
                primary_span,
                Some("duplicate endpoint name".to_string()),
            ));
            for &s in rest {
                if s == primary_span {
                    continue;
                }
                labels.push(LabeledSpan::new_with_span(None, s));
            }
            labels
        }
        ManifestError::UnknownEndpoint { name } => {
            let span = spans
                .provides
                .values()
                .find_map(|p| {
                    (p.endpoint_value.as_deref() == Some(name.as_str()))
                        .then_some(p.endpoint)
                        .flatten()
                })
                .unwrap_or_else(|| {
                    spans
                        .program
                        .as_ref()
                        .map(|p| p.whole)
                        .unwrap_or((0usize, 0usize).into())
                });
            vec![primary(
                span,
                Some("unknown endpoint referenced here".to_string()),
            )]
        }
        ManifestError::InvalidConfigSchema(_) => vec![primary(
            spans.config_schema.unwrap_or((0usize, 0usize).into()),
            Some("invalid schema here".to_string()),
        )],
        ManifestError::UnknownEnvironmentExtends { name, .. } => {
            let env = spans.environments.get(name.as_str());
            let span = env
                .and_then(|e| e.extends)
                .unwrap_or((0usize, 0usize).into());
            vec![primary(span, Some("unknown environment here".to_string()))]
        }
        ManifestError::EnvironmentCycle { name } => {
            let env = spans.environments.get(name.as_str());
            let span = env.map(|e| e.name).unwrap_or((0usize, 0usize).into());
            vec![primary(span, Some("cycle originates here".to_string()))]
        }
        ManifestError::UnknownComponentEnvironment { child, .. } => {
            let span = spans
                .components
                .get(child.as_str())
                .and_then(|c| c.environment.or(Some(c.name)))
                .unwrap_or((0usize, 0usize).into());
            vec![primary(
                span,
                Some("unknown environment referenced here".to_string()),
            )]
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

fn binding_target_key_for_span(span: &crate::BindingSpans) -> Option<crate::BindingTargetKey> {
    let to = span.to_value.as_deref()?;
    crate::binding_target_key_for_binding(to, span.slot_value.as_deref())
}
