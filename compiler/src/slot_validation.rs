#![allow(unused_assignments)]

use std::{collections::BTreeMap, sync::Arc};

use amber_manifest::{
    InterpolatedPart, InterpolatedString, InterpolationSource, Manifest, ManifestSpans, SlotDecl,
    SlotName, span_for_json_pointer,
};
use miette::{Diagnostic, NamedSource, Report, SourceSpan};
use thiserror::Error;

use crate::{
    frontend::{ResolvedNode, ResolvedTree},
    slot_query::{SlotQueryError, SlotTarget, parse_slot_query},
    store::{DigestStore, display_url},
};

#[derive(Debug, Error, Diagnostic)]
#[error("invalid slots interpolation in {component_path} ({location}): {message}")]
#[diagnostic(code(compiler::invalid_slots_interpolation), help("{help}"))]
struct InvalidSlotsInterpolation {
    component_path: String,
    location: String,
    message: String,
    help: String,
    #[source_code]
    src: NamedSource<Arc<str>>,
    #[label(primary, "{label}")]
    span: SourceSpan,
    label: String,
}

pub(crate) fn collect_slot_interpolation_diagnostics_from_tree(
    tree: &ResolvedTree,
    store: &DigestStore,
) -> Vec<Report> {
    let mut diagnostics = Vec::new();
    collect_slot_interpolation_diagnostics(&tree.root, "/", store, &mut diagnostics);
    diagnostics
}

fn collect_slot_interpolation_diagnostics(
    node: &ResolvedNode,
    component_path: &str,
    store: &DigestStore,
    diagnostics: &mut Vec<Report>,
) {
    let Some(manifest) = store.get(&node.digest) else {
        return;
    };
    let Some(stored) = store.get_source(&node.resolved_url) else {
        return;
    };

    let source = Arc::clone(&stored.source);
    let spans = stored.spans.as_ref();
    let src_name = display_url(&node.resolved_url);

    diagnostics.extend(validate_manifest_slot_interpolations(
        manifest.as_ref(),
        component_path,
        source,
        spans,
        &src_name,
    ));

    for (child_name, child) in &node.children {
        let child_path = if component_path == "/" {
            format!("/{child_name}")
        } else {
            format!("{component_path}/{child_name}")
        };
        collect_slot_interpolation_diagnostics(child, &child_path, store, diagnostics);
    }
}

fn validate_manifest_slot_interpolations(
    manifest: &Manifest,
    component_path: &str,
    source: Arc<str>,
    spans: &ManifestSpans,
    src_name: &str,
) -> Vec<Report> {
    let Some(program) = manifest.program() else {
        return Vec::new();
    };

    let mut diagnostics = Vec::new();
    let slots = manifest.slots();
    let ctx = SlotValidationContext {
        component_path,
        slots,
        source: &source,
        src_name,
    };

    for (idx, arg) in program.args.0.iter().enumerate() {
        let location = SlotLocation::Entrypoint(idx);
        let span = location.span(source.as_ref(), spans);
        validate_interpolated_string(arg, &ctx, location, span, &mut diagnostics);
    }

    for (key, value) in &program.env {
        let location = SlotLocation::Env(key.as_str());
        let span = location.span(source.as_ref(), spans);
        validate_interpolated_string(value, &ctx, location, span, &mut diagnostics);
    }

    diagnostics
}

#[derive(Clone, Copy, Debug)]
enum SlotLocation<'a> {
    Entrypoint(usize),
    Env(&'a str),
}

impl SlotLocation<'_> {
    fn label(self) -> String {
        match self {
            SlotLocation::Entrypoint(idx) => format!("program.entrypoint[{idx}]"),
            SlotLocation::Env(key) => format!("program.env.{key}"),
        }
    }

    fn span(self, source: &str, spans: &ManifestSpans) -> SourceSpan {
        let root = (0usize, source.len()).into();
        match self {
            SlotLocation::Entrypoint(idx) => {
                for key in ["args", "entrypoint"] {
                    let pointer = format!("/program/{key}/{idx}");
                    if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                        return span;
                    }
                }
                for key in ["args", "entrypoint"] {
                    let pointer = format!("/program/{key}");
                    if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                        return span;
                    }
                }
                spans
                    .program
                    .as_ref()
                    .map(|p| p.whole)
                    .unwrap_or_else(|| (0usize, 0usize).into())
            }
            SlotLocation::Env(key) => {
                let mut pointer = "/program/env/".to_string();
                push_json_pointer_segment(&mut pointer, key);
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                let fallback = span_for_json_pointer(source, root, "/program/env");
                fallback
                    .or_else(|| spans.program.as_ref().map(|p| p.whole))
                    .unwrap_or_else(|| (0usize, 0usize).into())
            }
        }
    }
}

struct SlotValidationContext<'a> {
    component_path: &'a str,
    slots: &'a BTreeMap<SlotName, SlotDecl>,
    source: &'a Arc<str>,
    src_name: &'a str,
}

fn validate_interpolated_string(
    value: &InterpolatedString,
    ctx: &SlotValidationContext<'_>,
    location: SlotLocation<'_>,
    span: SourceSpan,
    diagnostics: &mut Vec<Report>,
) {
    for part in &value.parts {
        let InterpolatedPart::Interpolation {
            source: kind,
            query,
        } = part
        else {
            continue;
        };
        if *kind != InterpolationSource::Slots {
            continue;
        }

        match parse_slot_query(query) {
            Ok(parsed) => match parsed.target {
                SlotTarget::All => {}
                SlotTarget::Slot(slot) => {
                    if !ctx.slots.contains_key(slot) {
                        let help = unknown_slot_help(ctx.component_path, ctx.slots);
                        diagnostics.push(Report::new(InvalidSlotsInterpolation {
                            component_path: ctx.component_path.to_string(),
                            location: location.label(),
                            message: format!("unknown slot `{slot}`"),
                            help,
                            src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                                .with_language("json5"),
                            span,
                            label: "slot interpolation here".to_string(),
                        }));
                    }
                }
            },
            Err(err) => {
                let help = slot_query_help(&err);
                diagnostics.push(Report::new(InvalidSlotsInterpolation {
                    component_path: ctx.component_path.to_string(),
                    location: location.label(),
                    message: err.to_string(),
                    help,
                    src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                        .with_language("json5"),
                    span,
                    label: "slot interpolation here".to_string(),
                }));
            }
        }
    }
}

fn slot_query_help(err: &SlotQueryError) -> String {
    match err {
        SlotQueryError::MissingSlotName => {
            "Use slots.<slot> or slots.<slot>.url (for example, slots.agent.url).".to_string()
        }
        SlotQueryError::EmptySegment { .. } => "Use dot-separated paths without empty segments \
                                                (for example, slots.agent.url)."
            .to_string(),
        SlotQueryError::UnsupportedField { .. } | SlotQueryError::UnsupportedPath { .. } => {
            "Supported slot fields: url.".to_string()
        }
    }
}

fn unknown_slot_help(component_path: &str, slots: &BTreeMap<SlotName, SlotDecl>) -> String {
    if slots.is_empty() {
        return format!(
            "No slots are declared on component {component_path}. Add slots in `slots: {{ ... }}` \
             or fix the reference."
        );
    }
    let mut names: Vec<_> = slots.keys().map(ToString::to_string).collect();
    names.sort();
    format!(
        "Valid slots on component {component_path}: {}",
        names.into_iter().take(20).collect::<Vec<_>>().join(", ")
    )
}

fn push_json_pointer_segment(out: &mut String, segment: &str) {
    for ch in segment.chars() {
        match ch {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            other => out.push(other),
        }
    }
}
