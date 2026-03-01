#![allow(unused_assignments)]

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use amber_json5::spans::span_for_object_key;
use amber_manifest::{
    BindingSource, BindingTarget, ComponentDecl, FrameworkBindingShape, InterpolatedPart,
    InterpolatedString, InterpolationSource, Manifest, ManifestSpans, MountSource,
    framework_capability, span_for_json_pointer,
};
use miette::{Diagnostic, NamedSource, Report, SourceSpan};
use serde_json::Value;
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

#[derive(Debug, Error, Diagnostic)]
#[error("component {component_path} never reads `{config_item}`")]
#[diagnostic(
    code(compiler::unused_config_binding_interpolation),
    severity(Warning),
    help("{help}\nConfigured by parent {parent_component_path} at `{parent_location}`.")
)]
struct UnusedConfigBindingInterpolation {
    component_path: String,
    config_item: String,
    parent_component_path: String,
    parent_location: String,
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
    named_url_unsupported: BTreeMap<String, String>,
    has_unnamed: bool,
}

#[derive(Default)]
struct ConfigUses {
    prefixes: BTreeSet<String>,
    uses_all: bool,
}

impl ConfigUses {
    fn add_query(&mut self, query: &str) {
        if self.uses_all {
            return;
        }
        if query.is_empty() {
            self.uses_all = true;
            self.prefixes.clear();
            return;
        }
        if query.split('.').any(|seg| seg.is_empty()) {
            return;
        }
        self.prefixes.insert(query.to_string());
    }

    fn is_used(&self, path: &str) -> bool {
        if self.uses_all {
            return true;
        }
        self.prefixes.iter().any(|prefix| {
            path == prefix
                || path
                    .strip_prefix(prefix.as_str())
                    .is_some_and(|rest| rest.starts_with('.'))
        })
    }
}

struct ChildConfigLintLabel {
    source: Arc<str>,
    src_name: String,
}

struct ChildConfigLintTarget {
    uses: ConfigUses,
    component_path: String,
    label: Option<ChildConfigLintLabel>,
}

pub(crate) type SuppressedUnusedConfigLints = BTreeMap<String, BTreeSet<String>>;

#[derive(Default)]
pub(crate) struct BindingInterpolationDiagnostics {
    pub(crate) diagnostics: Vec<Report>,
    pub(crate) suppressed_unused_config_lints: SuppressedUnusedConfigLints,
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
            if let Some(capability) = binding_url_unsupported(binding) {
                out.named_url_unsupported
                    .insert(name.to_string(), capability);
            }
        } else {
            out.has_unnamed = true;
        }
    }
    out
}

fn collect_bindings_in_manifest(manifest: &Manifest) -> BindingLookup {
    let mut out = BindingLookup::default();
    for binding in manifest.bindings().values() {
        if let Some(name) = binding.name.as_ref() {
            out.named.insert(name.to_string());
            if let Some(capability) = binding_url_unsupported(binding) {
                out.named_url_unsupported
                    .insert(name.to_string(), capability);
            }
        } else {
            out.has_unnamed = true;
        }
    }
    out
}

fn collect_config_uses(manifest: &Manifest) -> ConfigUses {
    let mut uses = ConfigUses::default();

    if let Some(program) = manifest.program() {
        if let Ok(image) = program.image.parse::<InterpolatedString>() {
            collect_config_uses_from_interpolated(&image, &mut uses);
        }
        for arg in &program.entrypoint.0 {
            collect_config_uses_from_interpolated(arg, &mut uses);
        }
        for value in program.env.values() {
            collect_config_uses_from_interpolated(value, &mut uses);
        }
        for mount in &program.mounts {
            match &mount.source {
                MountSource::Config(path) | MountSource::Secret(path) => uses.add_query(path),
                MountSource::Slot(_) | MountSource::Binding(_) | MountSource::Framework(_) => {}
                _ => {}
            }
        }
    }

    for decl in manifest.components().values() {
        let ComponentDecl::Object(obj) = decl else {
            continue;
        };
        let Some(config) = obj.config.as_ref() else {
            continue;
        };
        collect_config_uses_from_value(config, &mut uses);
    }

    uses
}

fn collect_config_uses_from_interpolated(value: &InterpolatedString, uses: &mut ConfigUses) {
    for part in &value.parts {
        let InterpolatedPart::Interpolation { source, query } = part else {
            continue;
        };
        if *source != InterpolationSource::Config {
            continue;
        }
        uses.add_query(query);
    }
}

fn collect_config_uses_from_value(value: &Value, uses: &mut ConfigUses) {
    match value {
        Value::String(s) => {
            let Ok(parsed) = s.parse::<InterpolatedString>() else {
                return;
            };
            collect_config_uses_from_interpolated(&parsed, uses);
        }
        Value::Array(values) => {
            for value in values {
                collect_config_uses_from_value(value, uses);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                collect_config_uses_from_value(value, uses);
            }
        }
        _ => {}
    }
}

fn binding_url_unsupported(binding: &amber_manifest::Binding) -> Option<String> {
    let BindingSource::Framework(name) = &binding.from else {
        return None;
    };
    let spec = framework_capability(name.as_str())
        .expect("manifest invariant: framework capability exists");
    match spec.binding_shape {
        FrameworkBindingShape::Url => None,
        FrameworkBindingShape::Opaque => Some(name.to_string()),
    }
}

pub(crate) fn collect_binding_interpolation_diagnostics_from_tree(
    tree: &ResolvedTree,
    store: &DigestStore,
) -> BindingInterpolationDiagnostics {
    let mut out = BindingInterpolationDiagnostics::default();
    let Some(root_manifest) = store.get(&tree.root.digest) else {
        return out;
    };
    let root_bindings =
        collect_bindings_for_target(root_manifest.as_ref(), BindingTargetSelector::Self_);
    collect_binding_interpolation_diagnostics(
        &tree.root,
        "/",
        store,
        root_bindings,
        &mut out.diagnostics,
        &mut out.suppressed_unused_config_lints,
    );
    out
}

fn collect_binding_interpolation_diagnostics(
    node: &ResolvedNode,
    component_path: &str,
    store: &DigestStore,
    bindings: BindingLookup,
    diagnostics: &mut Vec<Report>,
    suppressed_unused_config_lints: &mut SuppressedUnusedConfigLints,
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
        Arc::clone(&source),
        spans,
        &src_name,
    ));
    let mut child_targets: BTreeMap<String, ChildConfigLintTarget> = BTreeMap::new();
    for (child_name, child) in &node.children {
        let Some(child_manifest) = store.get(&child.digest) else {
            continue;
        };
        let child_component_path = if component_path == "/" {
            format!("/{child_name}")
        } else {
            format!("{component_path}/{child_name}")
        };
        let label = store
            .get_source(&child.resolved_url)
            .map(|stored| ChildConfigLintLabel {
                source: Arc::clone(&stored.source),
                src_name: display_url(&child.resolved_url),
            });
        child_targets.insert(
            child_name.to_string(),
            ChildConfigLintTarget {
                uses: collect_config_uses(child_manifest.as_ref()),
                component_path: child_component_path,
                label,
            },
        );
    }
    let config_bindings = collect_bindings_in_manifest(manifest.as_ref());
    let manifest_ctx = ManifestConfigValidationContext {
        component_path,
        bindings: config_bindings,
        source,
        spans,
        src_name: &src_name,
        child_targets: &child_targets,
    };
    diagnostics.extend(validate_manifest_config_binding_interpolations(
        manifest.as_ref(),
        manifest_ctx,
        suppressed_unused_config_lints,
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
            suppressed_unused_config_lints,
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

    if let Ok(image) = program.image.parse::<InterpolatedString>() {
        let location = ProgramLocation::Image;
        let span = location.span(source.as_ref(), spans);
        validate_interpolated_string(&image, &ctx, location, span, &mut diagnostics);
    }

    for (idx, arg) in program.entrypoint.0.iter().enumerate() {
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

struct ConfigBindingValidationContext<'a> {
    component_path: &'a str,
    bindings: &'a BindingLookup,
    child_target: Option<&'a ChildConfigLintTarget>,
    root_span: SourceSpan,
    config_span: Option<SourceSpan>,
    source: &'a Arc<str>,
    src_name: &'a str,
}

struct ManifestConfigValidationContext<'a> {
    component_path: &'a str,
    bindings: BindingLookup,
    source: Arc<str>,
    spans: &'a ManifestSpans,
    src_name: &'a str,
    child_targets: &'a BTreeMap<String, ChildConfigLintTarget>,
}

fn validate_manifest_config_binding_interpolations(
    manifest: &Manifest,
    manifest_ctx: ManifestConfigValidationContext<'_>,
    suppressed_unused_config_lints: &mut SuppressedUnusedConfigLints,
) -> Vec<Report> {
    let mut diagnostics = Vec::new();
    let root_span = (0usize, manifest_ctx.source.len()).into();

    for (child_name, decl) in manifest.components() {
        let ComponentDecl::Object(obj) = decl else {
            continue;
        };
        let Some(config) = obj.config.as_ref() else {
            continue;
        };

        let mut pointer = "/components/".to_string();
        push_json_pointer_segment(&mut pointer, child_name.as_str());
        pointer.push_str("/config");

        let location = format!("components.{child_name}.config");
        let config_span = manifest_ctx
            .spans
            .components
            .get(child_name.as_str())
            .and_then(|spans| spans.config);
        let ctx = ConfigBindingValidationContext {
            component_path: manifest_ctx.component_path,
            bindings: &manifest_ctx.bindings,
            child_target: manifest_ctx.child_targets.get(child_name.as_str()),
            root_span,
            config_span,
            source: &manifest_ctx.source,
            src_name: manifest_ctx.src_name,
        };

        validate_config_value(
            config,
            &ctx,
            &pointer,
            &location,
            "",
            &mut diagnostics,
            suppressed_unused_config_lints,
        );
    }

    diagnostics
}

fn validate_config_value(
    value: &Value,
    ctx: &ConfigBindingValidationContext<'_>,
    pointer: &str,
    location: &str,
    config_path: &str,
    diagnostics: &mut Vec<Report>,
    suppressed_unused_config_lints: &mut SuppressedUnusedConfigLints,
) {
    match value {
        Value::String(s) => {
            let Ok(parsed) = s.parse::<InterpolatedString>() else {
                return;
            };
            let span = span_for_json_pointer(ctx.source.as_ref(), ctx.root_span, pointer)
                .or(ctx.config_span)
                .unwrap_or_else(|| (0usize, 0usize).into());
            validate_interpolated_config_string(
                &parsed,
                ctx,
                location,
                config_path,
                span,
                diagnostics,
                suppressed_unused_config_lints,
            );
        }
        Value::Array(values) => {
            for (idx, value) in values.iter().enumerate() {
                let mut next_pointer = pointer.to_string();
                next_pointer.push('/');
                next_pointer.push_str(&idx.to_string());
                let next_location = format!("{location}[{idx}]");
                validate_config_value(
                    value,
                    ctx,
                    &next_pointer,
                    &next_location,
                    config_path,
                    diagnostics,
                    suppressed_unused_config_lints,
                );
            }
        }
        Value::Object(map) => {
            for (key, value) in map {
                let mut next_pointer = pointer.to_string();
                next_pointer.push('/');
                push_json_pointer_segment(&mut next_pointer, key);
                let next_location = format!("{location}.{key}");
                let next_path = if config_path.is_empty() {
                    key.clone()
                } else {
                    format!("{config_path}.{key}")
                };
                validate_config_value(
                    value,
                    ctx,
                    &next_pointer,
                    &next_location,
                    &next_path,
                    diagnostics,
                    suppressed_unused_config_lints,
                );
            }
        }
        _ => {}
    }
}

fn validate_interpolated_config_string(
    value: &InterpolatedString,
    ctx: &ConfigBindingValidationContext<'_>,
    location: &str,
    config_path: &str,
    span: SourceSpan,
    diagnostics: &mut Vec<Report>,
    suppressed_unused_config_lints: &mut SuppressedUnusedConfigLints,
) {
    let path_label = if config_path.is_empty() {
        "config".to_string()
    } else {
        format!("config.{config_path}")
    };
    let path_runtime_visible = ctx
        .child_target
        .is_none_or(|child_target| child_target.uses.is_used(config_path));

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

        if !path_runtime_visible {
            let Some(child_target) = ctx.child_target else {
                continue;
            };
            let Some(label) = child_target.label.as_ref() else {
                continue;
            };
            let Some(schema_span) = config_schema_property_span(label, config_path) else {
                continue;
            };
            if !config_path.is_empty() {
                suppressed_unused_config_lints
                    .entry(child_target.component_path.clone())
                    .or_default()
                    .insert(config_path.to_string());
            }
            diagnostics.push(Report::new(UnusedConfigBindingInterpolation {
                component_path: child_target.component_path.clone(),
                config_item: path_label.clone(),
                parent_component_path: ctx.component_path.to_string(),
                parent_location: location.to_string(),
                help: format!(
                    "Remove this config item from {}, or make {} read `{}` at runtime (for \
                     example by using `${{{}}}` in its program or by mounting it as a \
                     config/secret file).",
                    child_target.component_path,
                    child_target.component_path,
                    path_label,
                    path_label
                ),
                src: NamedSource::new(&label.src_name, Arc::clone(&label.source))
                    .with_language("json5"),
                span: schema_span,
                label: format!("unused config item `{path_label}`"),
            }));
            continue;
        }

        match parse_binding_query(query) {
            Ok(parsed) => {
                if !ctx.bindings.named.contains(parsed.name) {
                    let help = unknown_binding_help_for_config(ctx.component_path, ctx.bindings);
                    diagnostics.push(Report::new(InvalidBindingsInterpolation {
                        component_path: ctx.component_path.to_string(),
                        location: location.to_string(),
                        message: format!("unknown binding name `{}`", parsed.name),
                        help,
                        src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                            .with_language("json5"),
                        span,
                        label: "binding interpolation here".to_string(),
                    }));
                } else if let Some(capability) = ctx.bindings.named_url_unsupported.get(parsed.name)
                {
                    let help = non_url_binding_help(parsed.name, capability);
                    diagnostics.push(Report::new(InvalidBindingsInterpolation {
                        component_path: ctx.component_path.to_string(),
                        location: location.to_string(),
                        message: format!(
                            "binding `{}` does not expose a url (framework capability \
                             `framework.{capability}` is not URL-shaped)",
                            parsed.name
                        ),
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
                    location: location.to_string(),
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

#[derive(Clone, Copy, Debug)]
enum ProgramLocation<'a> {
    Image,
    Entrypoint(usize),
    Env(&'a str),
}

impl ProgramLocation<'_> {
    fn label(self) -> String {
        match self {
            ProgramLocation::Image => "program.image".to_string(),
            ProgramLocation::Entrypoint(idx) => format!("program.entrypoint[{idx}]"),
            ProgramLocation::Env(key) => format!("program.env.{key}"),
        }
    }

    fn span(self, source: &str, spans: &ManifestSpans) -> SourceSpan {
        let root = (0usize, source.len()).into();
        match self {
            ProgramLocation::Image => span_for_json_pointer(source, root, "/program/image")
                .or_else(|| spans.program.as_ref().map(|p| p.whole))
                .unwrap_or_else(|| (0usize, 0usize).into()),
            ProgramLocation::Entrypoint(idx) => {
                let pointer = format!("/program/entrypoint/{idx}");
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                if let Some(span) = span_for_json_pointer(source, root, "/program/entrypoint") {
                    return span;
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
                } else if let Some(capability) = ctx.bindings.named_url_unsupported.get(parsed.name)
                {
                    let help = non_url_binding_help(parsed.name, capability);
                    diagnostics.push(Report::new(InvalidBindingsInterpolation {
                        component_path: ctx.component_path.to_string(),
                        location: location.label(),
                        message: format!(
                            "binding `{}` does not expose a url (framework capability \
                             `framework.{capability}` is not URL-shaped)",
                            parsed.name
                        ),
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

fn unknown_binding_help_for_config(component_path: &str, bindings: &BindingLookup) -> String {
    if bindings.named.is_empty() {
        if bindings.has_unnamed {
            return format!(
                "Bindings declared in component {component_path} are unnamed. Add `name` to the \
                 binding you want to reference."
            );
        }
        return format!(
            "Component {component_path} declares no bindings. Add a named binding or fix the \
             reference."
        );
    }
    let names = bindings
        .named
        .iter()
        .take(20)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    format!("Named bindings declared in component {component_path}: {names}")
}

fn non_url_binding_help(binding: &str, capability: &str) -> String {
    format!(
        "Binding `{binding}` targets framework.{capability}, which does not expose a URL. Remove \
         the interpolation or use a URL-shaped binding."
    )
}

fn config_schema_property_span(
    label: &ChildConfigLintLabel,
    config_path: &str,
) -> Option<SourceSpan> {
    if config_path.is_empty() {
        return None;
    }
    if config_path.split('.').any(|seg| seg.is_empty()) {
        return None;
    }

    let root = (0usize, label.source.len()).into();
    let segments = config_path.split('.').collect::<Vec<_>>();
    let (last, parents) = segments.split_last()?;

    let mut parent_properties_pointer = "/config_schema/properties".to_string();
    for segment in parents {
        parent_properties_pointer.push('/');
        push_json_pointer_segment(&mut parent_properties_pointer, segment);
        parent_properties_pointer.push_str("/properties");
    }

    let parent_properties_span =
        span_for_json_pointer(label.source.as_ref(), root, &parent_properties_pointer)?;

    let key_span = span_for_object_key(label.source.as_ref(), parent_properties_span, last)?;

    let mut value_pointer = parent_properties_pointer;
    value_pointer.push('/');
    push_json_pointer_segment(&mut value_pointer, last);
    let value_span = span_for_json_pointer(label.source.as_ref(), root, &value_pointer)?;

    let start = key_span.offset();
    let end = value_span.offset().saturating_add(value_span.len());
    Some((start, end.saturating_sub(start)).into())
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[test]
    fn bindings_interpolation_rejects_non_url_framework_binding() {
        let bindings = BindingLookup {
            named: BTreeSet::from(["bind".to_string()]),
            named_url_unsupported: BTreeMap::from([(
                "bind".to_string(),
                "dynamic_children".to_string(),
            )]),
            has_unnamed: false,
        };
        let source: Arc<str> = Arc::from("${bindings.bind.url}");
        let ctx = BindingValidationContext {
            component_path: "/",
            bindings: &bindings,
            source: &source,
            src_name: "<test>",
        };

        let value: InterpolatedString = "${bindings.bind.url}".parse().unwrap();
        let mut diagnostics = Vec::new();
        validate_interpolated_string(
            &value,
            &ctx,
            ProgramLocation::Entrypoint(0),
            (0usize, 0usize).into(),
            &mut diagnostics,
        );

        assert_eq!(diagnostics.len(), 1);
        let message = diagnostics[0].to_string();
        assert!(message.contains("does not expose a url"), "{message}");
        assert!(message.contains("framework.dynamic_children"), "{message}");
    }
}
