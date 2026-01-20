#![allow(unused_assignments)]

use std::{collections::BTreeSet, sync::Arc};

use amber_manifest::{
    BindingTarget, InterpolatedPart, InterpolatedString, InterpolationSource, Manifest,
    ManifestSpans, span_for_json_pointer,
};
use miette::{Diagnostic, NamedSource, Report, SourceSpan};
use thiserror::Error;

use crate::{
    binding_query::{BindingQueryError, parse_binding_query},
    frontend::{ResolvedNode, ResolvedTree},
    store::{DigestStore, display_url},
};

#[derive(Debug, Error, Diagnostic)]
#[error("invalid bindings interpolation in {component_path} ({location}): {message}")]
#[diagnostic(code(compiler::invalid_bindings_interpolation), help("{help}"))]
struct InvalidBindingsInterpolation {
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

#[derive(Default)]
struct BindingLookup {
    named: BTreeSet<String>,
    has_unnamed: bool,
}

enum BindingTargetSelector<'a> {
    Self_,
    Child(&'a str),
}

fn collect_bindings_for_target(
    manifest: &Manifest,
    selector: BindingTargetSelector<'_>,
) -> BindingLookup {
    let mut out = BindingLookup::default();
    for (target, binding) in manifest.bindings() {
        let matches = match (target, &selector) {
            (BindingTarget::SelfSlot(_), BindingTargetSelector::Self_) => true,
            (BindingTarget::ChildSlot { child, .. }, BindingTargetSelector::Child(name)) => {
                child.as_str() == *name
            }
            _ => false,
        };
        if !matches {
            continue;
        }
        if let Some(name) = binding.name.as_ref() {
            out.named.insert(name.to_string());
        } else {
            out.has_unnamed = true;
        }
    }
    out
}

pub(crate) fn collect_binding_interpolation_diagnostics_from_tree(
    tree: &ResolvedTree,
    store: &DigestStore,
) -> Vec<Report> {
    let mut diagnostics = Vec::new();
    let Some(root_manifest) = store.get(&tree.root.digest) else {
        return diagnostics;
    };
    let root_bindings =
        collect_bindings_for_target(root_manifest.as_ref(), BindingTargetSelector::Self_);
    collect_binding_interpolation_diagnostics(
        &tree.root,
        "/",
        store,
        root_bindings,
        &mut diagnostics,
    );
    diagnostics
}

fn collect_binding_interpolation_diagnostics(
    node: &ResolvedNode,
    component_path: &str,
    store: &DigestStore,
    bindings: BindingLookup,
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

    diagnostics.extend(validate_manifest_binding_interpolations(
        manifest.as_ref(),
        component_path,
        bindings,
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
        let child_bindings = collect_bindings_for_target(
            manifest.as_ref(),
            BindingTargetSelector::Child(child_name),
        );
        collect_binding_interpolation_diagnostics(
            child,
            &child_path,
            store,
            child_bindings,
            diagnostics,
        );
    }
}

fn validate_manifest_binding_interpolations(
    manifest: &Manifest,
    component_path: &str,
    bindings: BindingLookup,
    source: Arc<str>,
    spans: &ManifestSpans,
    src_name: &str,
) -> Vec<Report> {
    let Some(program) = manifest.program() else {
        return Vec::new();
    };

    let mut diagnostics = Vec::new();
    let ctx = BindingValidationContext {
        component_path,
        bindings: &bindings,
        source: &source,
        src_name,
    };

    for (idx, arg) in program.args.0.iter().enumerate() {
        let location = ProgramLocation::Entrypoint(idx);
        let span = location.span(source.as_ref(), spans);
        validate_interpolated_string(arg, &ctx, location, span, &mut diagnostics);
    }

    for (key, value) in &program.env {
        let location = ProgramLocation::Env(key.as_str());
        let span = location.span(source.as_ref(), spans);
        validate_interpolated_string(value, &ctx, location, span, &mut diagnostics);
    }

    diagnostics
}

#[derive(Clone, Copy, Debug)]
enum ProgramLocation<'a> {
    Entrypoint(usize),
    Env(&'a str),
}

impl ProgramLocation<'_> {
    fn label(self) -> String {
        match self {
            ProgramLocation::Entrypoint(idx) => format!("program.entrypoint[{idx}]"),
            ProgramLocation::Env(key) => format!("program.env.{key}"),
        }
    }

    fn span(self, source: &str, spans: &ManifestSpans) -> SourceSpan {
        let root = (0usize, source.len()).into();
        match self {
            ProgramLocation::Entrypoint(idx) => {
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
            ProgramLocation::Env(key) => {
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

struct BindingValidationContext<'a> {
    component_path: &'a str,
    bindings: &'a BindingLookup,
    source: &'a Arc<str>,
    src_name: &'a str,
}

fn validate_interpolated_string(
    value: &InterpolatedString,
    ctx: &BindingValidationContext<'_>,
    location: ProgramLocation<'_>,
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
        if *kind != InterpolationSource::Bindings {
            continue;
        }

        match parse_binding_query(query) {
            Ok(parsed) => {
                if !ctx.bindings.named.contains(parsed.name) {
                    let help = unknown_binding_help(ctx.component_path, ctx.bindings);
                    diagnostics.push(Report::new(InvalidBindingsInterpolation {
                        component_path: ctx.component_path.to_string(),
                        location: location.label(),
                        message: format!("unknown binding name `{}`", parsed.name),
                        help,
                        src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                            .with_language("json5"),
                        span,
                        label: "binding interpolation here".to_string(),
                    }));
                }
            }
            Err(err) => {
                let help = binding_query_help(&err);
                diagnostics.push(Report::new(InvalidBindingsInterpolation {
                    component_path: ctx.component_path.to_string(),
                    location: location.label(),
                    message: err.to_string(),
                    help,
                    src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                        .with_language("json5"),
                    span,
                    label: "binding interpolation here".to_string(),
                }));
            }
        }
    }
}

fn binding_query_help(err: &BindingQueryError) -> String {
    match err {
        BindingQueryError::MissingBindingName | BindingQueryError::MissingField => {
            "Use bindings.<name>.url (for example, bindings.route.url).".to_string()
        }
        BindingQueryError::EmptySegment { .. } => "Use dot-separated paths without empty segments \
                                                   (for example, bindings.route.url)."
            .to_string(),
        BindingQueryError::UnsupportedField { .. } | BindingQueryError::UnsupportedPath { .. } => {
            "Supported binding fields: url.".to_string()
        }
    }
}

fn unknown_binding_help(component_path: &str, bindings: &BindingLookup) -> String {
    if bindings.named.is_empty() {
        if bindings.has_unnamed {
            return format!(
                "Bindings targeting component {component_path} are unnamed. Add `name` to the \
                 binding you want to reference."
            );
        }
        return format!(
            "No bindings target component {component_path}. Add a named binding in the parent \
             manifest or fix the reference."
        );
    }
    let names = bindings
        .named
        .iter()
        .take(20)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    format!("Named bindings targeting component {component_path}: {names}")
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
