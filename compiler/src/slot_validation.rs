#![allow(unused_assignments)]

use std::{collections::BTreeMap, sync::Arc};

use amber_manifest::{
    CapabilityKind, InterpolatedPart, InterpolatedString, InterpolationSource, Manifest,
    ManifestSpans, Program, SlotDecl, SlotName, span_for_json_pointer,
    validate_slot_query_for_slot,
};
use jsonptr::PointerBuf;
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

    match program {
        Program::Image(program) => {
            if let Ok(image) = program.image.parse::<InterpolatedString>() {
                let location = SlotLocation::Image;
                let span = location.span(source.as_ref(), spans);
                validate_interpolated_string(&image, &ctx, location, span, false, &mut diagnostics);
            }

            for (idx, item) in program.entrypoint.0.iter().enumerate() {
                match item {
                    amber_manifest::ProgramArgItem::Arg(arg) => {
                        let location = SlotLocation::Entrypoint(idx);
                        let span = location.span(source.as_ref(), spans);
                        validate_interpolated_string(
                            arg,
                            &ctx,
                            location,
                            span,
                            false,
                            &mut diagnostics,
                        );
                    }
                    amber_manifest::ProgramArgItem::Group(group) => {
                        if group.when.source() == InterpolationSource::Slots {
                            let location = SlotLocation::EntrypointCondition(idx);
                            let span = location.span(source.as_ref(), spans);
                            validate_slot_condition(
                                group.when.query(),
                                &ctx,
                                location,
                                span,
                                &mut diagnostics,
                            );
                        }
                        for (group_idx, arg) in group.argv.0.iter().enumerate() {
                            let location = SlotLocation::EntrypointGroup(idx, group_idx);
                            let span = location.span(source.as_ref(), spans);
                            validate_interpolated_string(
                                arg,
                                &ctx,
                                location,
                                span,
                                false,
                                &mut diagnostics,
                            );
                        }
                    }
                    amber_manifest::ProgramArgItem::RepeatedArgv(repeated) => {
                        let location = SlotLocation::EntrypointEach(idx);
                        let span = location.span(source.as_ref(), spans);
                        validate_repeated_each(
                            repeated.each.slot(),
                            &ctx,
                            location,
                            span,
                            &mut diagnostics,
                        );
                        if let Some(when) = repeated.when.as_ref()
                            && when.source() == InterpolationSource::Slots
                        {
                            let location = SlotLocation::EntrypointCondition(idx);
                            let span = location.span(source.as_ref(), spans);
                            validate_slot_condition(
                                when.query(),
                                &ctx,
                                location,
                                span,
                                &mut diagnostics,
                            );
                        }
                        for (group_idx, arg) in repeated.argv.0.iter().enumerate() {
                            let location = SlotLocation::EntrypointGroup(idx, group_idx);
                            let span = location.span(source.as_ref(), spans);
                            validate_interpolated_string(
                                arg,
                                &ctx,
                                location,
                                span,
                                true,
                                &mut diagnostics,
                            );
                        }
                    }
                    amber_manifest::ProgramArgItem::RepeatedArg(repeated) => {
                        let location = SlotLocation::EntrypointEach(idx);
                        let span = location.span(source.as_ref(), spans);
                        validate_repeated_each(
                            repeated.each.slot(),
                            &ctx,
                            location,
                            span,
                            &mut diagnostics,
                        );
                        if let Some(when) = repeated.when.as_ref()
                            && when.source() == InterpolationSource::Slots
                        {
                            let location = SlotLocation::EntrypointCondition(idx);
                            let span = location.span(source.as_ref(), spans);
                            validate_slot_condition(
                                when.query(),
                                &ctx,
                                location,
                                span,
                                &mut diagnostics,
                            );
                        }
                        let location = SlotLocation::Entrypoint(idx);
                        let span = location.span(source.as_ref(), spans);
                        validate_interpolated_string(
                            &repeated.arg,
                            &ctx,
                            location,
                            span,
                            true,
                            &mut diagnostics,
                        );
                    }
                }
            }
        }
        Program::Path(program) => {
            if let Ok(path) = program.path.parse::<InterpolatedString>() {
                let location = SlotLocation::Path;
                let span = location.span(source.as_ref(), spans);
                validate_interpolated_string(&path, &ctx, location, span, false, &mut diagnostics);
            }

            for (idx, item) in program.args.0.iter().enumerate() {
                match item {
                    amber_manifest::ProgramArgItem::Arg(arg) => {
                        let location = SlotLocation::Args(idx);
                        let span = location.span(source.as_ref(), spans);
                        validate_interpolated_string(
                            arg,
                            &ctx,
                            location,
                            span,
                            false,
                            &mut diagnostics,
                        );
                    }
                    amber_manifest::ProgramArgItem::Group(group) => {
                        if group.when.source() == InterpolationSource::Slots {
                            let location = SlotLocation::ArgsCondition(idx);
                            let span = location.span(source.as_ref(), spans);
                            validate_slot_condition(
                                group.when.query(),
                                &ctx,
                                location,
                                span,
                                &mut diagnostics,
                            );
                        }
                        for (group_idx, arg) in group.argv.0.iter().enumerate() {
                            let location = SlotLocation::ArgsGroup(idx, group_idx);
                            let span = location.span(source.as_ref(), spans);
                            validate_interpolated_string(
                                arg,
                                &ctx,
                                location,
                                span,
                                false,
                                &mut diagnostics,
                            );
                        }
                    }
                    amber_manifest::ProgramArgItem::RepeatedArgv(repeated) => {
                        let location = SlotLocation::ArgsEach(idx);
                        let span = location.span(source.as_ref(), spans);
                        validate_repeated_each(
                            repeated.each.slot(),
                            &ctx,
                            location,
                            span,
                            &mut diagnostics,
                        );
                        if let Some(when) = repeated.when.as_ref()
                            && when.source() == InterpolationSource::Slots
                        {
                            let location = SlotLocation::ArgsCondition(idx);
                            let span = location.span(source.as_ref(), spans);
                            validate_slot_condition(
                                when.query(),
                                &ctx,
                                location,
                                span,
                                &mut diagnostics,
                            );
                        }
                        for (group_idx, arg) in repeated.argv.0.iter().enumerate() {
                            let location = SlotLocation::ArgsGroup(idx, group_idx);
                            let span = location.span(source.as_ref(), spans);
                            validate_interpolated_string(
                                arg,
                                &ctx,
                                location,
                                span,
                                true,
                                &mut diagnostics,
                            );
                        }
                    }
                    amber_manifest::ProgramArgItem::RepeatedArg(repeated) => {
                        let location = SlotLocation::ArgsEach(idx);
                        let span = location.span(source.as_ref(), spans);
                        validate_repeated_each(
                            repeated.each.slot(),
                            &ctx,
                            location,
                            span,
                            &mut diagnostics,
                        );
                        if let Some(when) = repeated.when.as_ref()
                            && when.source() == InterpolationSource::Slots
                        {
                            let location = SlotLocation::ArgsCondition(idx);
                            let span = location.span(source.as_ref(), spans);
                            validate_slot_condition(
                                when.query(),
                                &ctx,
                                location,
                                span,
                                &mut diagnostics,
                            );
                        }
                        let location = SlotLocation::Args(idx);
                        let span = location.span(source.as_ref(), spans);
                        validate_interpolated_string(
                            &repeated.arg,
                            &ctx,
                            location,
                            span,
                            true,
                            &mut diagnostics,
                        );
                    }
                }
            }
        }
        Program::Vm(program) => {
            if let Ok(image) = program.0.image.parse::<InterpolatedString>() {
                let location = SlotLocation::VmImage;
                let span = location.span(source.as_ref(), spans);
                validate_interpolated_string(&image, &ctx, location, span, false, &mut diagnostics);
            }
            if let Some(raw) = program.0.cloud_init.user_data.as_deref()
                && let Ok(user_data) = raw.parse::<InterpolatedString>()
            {
                let location = SlotLocation::VmCloudInitUserData;
                let span = location.span(source.as_ref(), spans);
                validate_interpolated_string(
                    &user_data,
                    &ctx,
                    location,
                    span,
                    false,
                    &mut diagnostics,
                );
            }
            if let Some(raw) = program.0.cloud_init.vendor_data.as_deref()
                && let Ok(vendor_data) = raw.parse::<InterpolatedString>()
            {
                let location = SlotLocation::VmCloudInitVendorData;
                let span = location.span(source.as_ref(), spans);
                validate_interpolated_string(
                    &vendor_data,
                    &ctx,
                    location,
                    span,
                    false,
                    &mut diagnostics,
                );
            }
        }
        _ => {}
    }

    if matches!(program, Program::Vm(_)) {
        return diagnostics;
    }

    let env_location = |key| SlotLocation::Env(key);
    let env_condition_location = |key| SlotLocation::EnvCondition(key);
    let env_each_location = |key| SlotLocation::EnvEach(key);
    let env_value_location = |key| SlotLocation::EnvValue(key);

    for (key, value) in program.env() {
        match value {
            amber_manifest::ProgramEnvValue::Value(value) => {
                let location = env_location(key.as_str());
                let span = location.span(source.as_ref(), spans);
                validate_interpolated_string(value, &ctx, location, span, false, &mut diagnostics);
            }
            amber_manifest::ProgramEnvValue::Group(group) => {
                if group.when.source() == InterpolationSource::Slots {
                    let location = env_condition_location(key.as_str());
                    let span = location.span(source.as_ref(), spans);
                    validate_slot_condition(
                        group.when.query(),
                        &ctx,
                        location,
                        span,
                        &mut diagnostics,
                    );
                }
                let location = env_value_location(key.as_str());
                let span = location.span(source.as_ref(), spans);
                validate_interpolated_string(
                    &group.value,
                    &ctx,
                    location,
                    span,
                    false,
                    &mut diagnostics,
                );
            }
            amber_manifest::ProgramEnvValue::Repeated(repeated) => {
                let location = env_each_location(key.as_str());
                let span = location.span(source.as_ref(), spans);
                validate_repeated_each(
                    repeated.each.slot(),
                    &ctx,
                    location,
                    span,
                    &mut diagnostics,
                );
                if let Some(when) = repeated.when.as_ref()
                    && when.source() == InterpolationSource::Slots
                {
                    let location = env_condition_location(key.as_str());
                    let span = location.span(source.as_ref(), spans);
                    validate_slot_condition(when.query(), &ctx, location, span, &mut diagnostics);
                }
                let location = env_value_location(key.as_str());
                let span = location.span(source.as_ref(), spans);
                validate_interpolated_string(
                    &repeated.value,
                    &ctx,
                    location,
                    span,
                    true,
                    &mut diagnostics,
                );
            }
        }
    }

    diagnostics
}

#[derive(Clone, Copy, Debug)]
enum SlotLocation<'a> {
    Image,
    Path,
    VmImage,
    VmCloudInitUserData,
    VmCloudInitVendorData,
    Entrypoint(usize),
    EntrypointCondition(usize),
    EntrypointEach(usize),
    EntrypointGroup(usize, usize),
    Args(usize),
    ArgsCondition(usize),
    ArgsEach(usize),
    ArgsGroup(usize, usize),
    Env(&'a str),
    EnvCondition(&'a str),
    EnvEach(&'a str),
    EnvValue(&'a str),
}

impl SlotLocation<'_> {
    fn label(self) -> String {
        match self {
            SlotLocation::Image => "program.image".to_string(),
            SlotLocation::Path => "program.path".to_string(),
            SlotLocation::VmImage => "program.vm.image".to_string(),
            SlotLocation::VmCloudInitUserData => "program.vm.cloud_init.user_data".to_string(),
            SlotLocation::VmCloudInitVendorData => "program.vm.cloud_init.vendor_data".to_string(),
            SlotLocation::Entrypoint(idx) => format!("program.entrypoint[{idx}]"),
            SlotLocation::EntrypointCondition(idx) => format!("program.entrypoint[{idx}].when"),
            SlotLocation::EntrypointEach(idx) => format!("program.entrypoint[{idx}].each"),
            SlotLocation::EntrypointGroup(idx, group_idx) => {
                format!("program.entrypoint[{idx}].argv[{group_idx}]")
            }
            SlotLocation::Args(idx) => format!("program.args[{idx}]"),
            SlotLocation::ArgsCondition(idx) => format!("program.args[{idx}].when"),
            SlotLocation::ArgsEach(idx) => format!("program.args[{idx}].each"),
            SlotLocation::ArgsGroup(idx, group_idx) => {
                format!("program.args[{idx}].argv[{group_idx}]")
            }
            SlotLocation::Env(key) => format!("program.env.{key}"),
            SlotLocation::EnvCondition(key) => format!("program.env.{key}.when"),
            SlotLocation::EnvEach(key) => format!("program.env.{key}.each"),
            SlotLocation::EnvValue(key) => format!("program.env.{key}.value"),
        }
    }

    fn span(self, source: &str, spans: &ManifestSpans) -> SourceSpan {
        let root = (0usize, source.len()).into();
        match self {
            SlotLocation::Image => span_for_json_pointer(source, root, "/program/image")
                .or_else(|| spans.program.as_ref().map(|p| p.whole))
                .unwrap_or_else(|| (0usize, 0usize).into()),
            SlotLocation::Path => span_for_json_pointer(source, root, "/program/path")
                .or_else(|| spans.program.as_ref().map(|p| p.whole))
                .unwrap_or_else(|| (0usize, 0usize).into()),
            SlotLocation::VmImage => span_for_json_pointer(source, root, "/program/vm/image")
                .or_else(|| spans.program.as_ref().map(|p| p.whole))
                .unwrap_or_else(|| (0usize, 0usize).into()),
            SlotLocation::VmCloudInitUserData => {
                span_for_json_pointer(source, root, "/program/vm/cloud_init/user_data")
                    .or_else(|| spans.program.as_ref().map(|p| p.whole))
                    .unwrap_or_else(|| (0usize, 0usize).into())
            }
            SlotLocation::VmCloudInitVendorData => {
                span_for_json_pointer(source, root, "/program/vm/cloud_init/vendor_data")
                    .or_else(|| spans.program.as_ref().map(|p| p.whole))
                    .unwrap_or_else(|| (0usize, 0usize).into())
            }
            SlotLocation::Entrypoint(idx) => {
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
            SlotLocation::EntrypointCondition(idx) => {
                let pointer = format!("/program/entrypoint/{idx}/when");
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                let outer = format!("/program/entrypoint/{idx}");
                if let Some(span) = span_for_json_pointer(source, root, &outer) {
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
            SlotLocation::EntrypointEach(idx) => {
                let pointer = format!("/program/entrypoint/{idx}/each");
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                let outer = format!("/program/entrypoint/{idx}");
                if let Some(span) = span_for_json_pointer(source, root, &outer) {
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
            SlotLocation::EntrypointGroup(idx, group_idx) => {
                let pointer = format!("/program/entrypoint/{idx}/argv/{group_idx}");
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                let outer = format!("/program/entrypoint/{idx}");
                if let Some(span) = span_for_json_pointer(source, root, &outer) {
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
            SlotLocation::Args(idx) => {
                let pointer = format!("/program/args/{idx}");
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                if let Some(span) = span_for_json_pointer(source, root, "/program/args") {
                    return span;
                }
                spans
                    .program
                    .as_ref()
                    .map(|p| p.whole)
                    .unwrap_or_else(|| (0usize, 0usize).into())
            }
            SlotLocation::ArgsCondition(idx) => {
                let pointer = format!("/program/args/{idx}/when");
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                let outer = format!("/program/args/{idx}");
                if let Some(span) = span_for_json_pointer(source, root, &outer) {
                    return span;
                }
                if let Some(span) = span_for_json_pointer(source, root, "/program/args") {
                    return span;
                }
                spans
                    .program
                    .as_ref()
                    .map(|p| p.whole)
                    .unwrap_or_else(|| (0usize, 0usize).into())
            }
            SlotLocation::ArgsEach(idx) => {
                let pointer = format!("/program/args/{idx}/each");
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                let outer = format!("/program/args/{idx}");
                if let Some(span) = span_for_json_pointer(source, root, &outer) {
                    return span;
                }
                if let Some(span) = span_for_json_pointer(source, root, "/program/args") {
                    return span;
                }
                spans
                    .program
                    .as_ref()
                    .map(|p| p.whole)
                    .unwrap_or_else(|| (0usize, 0usize).into())
            }
            SlotLocation::ArgsGroup(idx, group_idx) => {
                let pointer = format!("/program/args/{idx}/argv/{group_idx}");
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                let outer = format!("/program/args/{idx}");
                if let Some(span) = span_for_json_pointer(source, root, &outer) {
                    return span;
                }
                if let Some(span) = span_for_json_pointer(source, root, "/program/args") {
                    return span;
                }
                spans
                    .program
                    .as_ref()
                    .map(|p| p.whole)
                    .unwrap_or_else(|| (0usize, 0usize).into())
            }
            SlotLocation::Env(key) => {
                let pointer = PointerBuf::from_tokens(["program", "env", key]).to_string();
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                let fallback = span_for_json_pointer(source, root, "/program/env");
                fallback
                    .or_else(|| spans.program.as_ref().map(|p| p.whole))
                    .unwrap_or_else(|| (0usize, 0usize).into())
            }
            SlotLocation::EnvCondition(key) => {
                let pointer = PointerBuf::from_tokens(["program", "env", key, "when"]).to_string();
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                let outer = PointerBuf::from_tokens(["program", "env", key]).to_string();
                if let Some(span) = span_for_json_pointer(source, root, &outer) {
                    return span;
                }
                let fallback = span_for_json_pointer(source, root, "/program/env");
                fallback
                    .or_else(|| spans.program.as_ref().map(|p| p.whole))
                    .unwrap_or_else(|| (0usize, 0usize).into())
            }
            SlotLocation::EnvEach(key) => {
                let pointer = PointerBuf::from_tokens(["program", "env", key, "each"]).to_string();
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                let outer = PointerBuf::from_tokens(["program", "env", key]).to_string();
                if let Some(span) = span_for_json_pointer(source, root, &outer) {
                    return span;
                }
                let fallback = span_for_json_pointer(source, root, "/program/env");
                fallback
                    .or_else(|| spans.program.as_ref().map(|p| p.whole))
                    .unwrap_or_else(|| (0usize, 0usize).into())
            }
            SlotLocation::EnvValue(key) => {
                let pointer = PointerBuf::from_tokens(["program", "env", key, "value"]).to_string();
                if let Some(span) = span_for_json_pointer(source, root, &pointer) {
                    return span;
                }
                let outer = PointerBuf::from_tokens(["program", "env", key]).to_string();
                if let Some(span) = span_for_json_pointer(source, root, &outer) {
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

fn validate_repeated_each(
    slot_name: &str,
    ctx: &SlotValidationContext<'_>,
    location: SlotLocation<'_>,
    span: SourceSpan,
    diagnostics: &mut Vec<Report>,
) {
    let Some(slot_decl) = ctx.slots.get(slot_name) else {
        let help = unknown_slot_help(ctx.component_path, ctx.slots);
        diagnostics.push(Report::new(InvalidSlotsInterpolation {
            component_path: ctx.component_path.to_string(),
            location: location.label(),
            message: format!("unknown slot `{slot_name}`"),
            help,
            src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source)).with_language("json5"),
            span,
            label: "repeated slot expansion here".to_string(),
        }));
        return;
    };
    if !slot_decl.multiple {
        diagnostics.push(Report::new(InvalidSlotsInterpolation {
            component_path: ctx.component_path.to_string(),
            location: location.label(),
            message: format!("slot `{slot_name}` is not declared with `multiple: true`"),
            help: format!("declare slot `{slot_name}` with `multiple: true` before using `each`"),
            src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source)).with_language("json5"),
            span,
            label: "repeated slot expansion here".to_string(),
        }));
    }
}

fn validate_slot_condition(
    query: &str,
    ctx: &SlotValidationContext<'_>,
    location: SlotLocation<'_>,
    span: SourceSpan,
    diagnostics: &mut Vec<Report>,
) {
    match parse_slot_query(query) {
        Ok(parsed) => match parsed.target {
            SlotTarget::All => {}
            SlotTarget::Slot(slot) => {
                let Some(slot_decl) = ctx.slots.get(slot) else {
                    let help = unknown_slot_help(ctx.component_path, ctx.slots);
                    diagnostics.push(Report::new(InvalidSlotsInterpolation {
                        component_path: ctx.component_path.to_string(),
                        location: location.label(),
                        message: format!("unknown slot `{slot}`"),
                        help,
                        src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                            .with_language("json5"),
                        span,
                        label: "slot condition here".to_string(),
                    }));
                    return;
                };

                if let Err(err) = validate_slot_query_for_slot(slot_decl, &parsed) {
                    let help = slot_query_help(Some(slot), &err);
                    diagnostics.push(Report::new(InvalidSlotsInterpolation {
                        component_path: ctx.component_path.to_string(),
                        location: location.label(),
                        message: err.to_string(),
                        help,
                        src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                            .with_language("json5"),
                        span,
                        label: "slot condition here".to_string(),
                    }));
                }
            }
        },
        Err(err) => {
            let help = slot_query_help(None, &err);
            diagnostics.push(Report::new(InvalidSlotsInterpolation {
                component_path: ctx.component_path.to_string(),
                location: location.label(),
                message: err.to_string(),
                help,
                src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source)).with_language("json5"),
                span,
                label: "slot condition here".to_string(),
            }));
        }
    }
}

struct SlotValidationContext<'a> {
    component_path: &'a str,
    slots: &'a BTreeMap<SlotName, SlotDecl>,
    source: &'a Arc<str>,
    src_name: &'a str,
}

#[derive(Debug)]
enum ItemQueryError {
    EmptySegment { query: String },
    UnknownField { field: String },
    UnknownPath { path: String },
}

impl std::fmt::Display for ItemQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptySegment { query } => {
                write!(f, "invalid item path {query:?}: empty segment")
            }
            Self::UnknownField { field } => write!(f, "unknown item field {field:?}"),
            Self::UnknownPath { path } => write!(f, "unknown item path {path:?}"),
        }
    }
}

fn validate_item_query(query: &str) -> Result<(), ItemQueryError> {
    if query.is_empty() {
        return Ok(());
    }

    let mut segments = query.split('.');
    let field = segments
        .next()
        .expect("split on '.' yields at least one segment");
    let rest: Vec<&str> = segments.collect();
    if field.is_empty() || rest.iter().any(|segment| segment.is_empty()) {
        return Err(ItemQueryError::EmptySegment {
            query: format!("item.{query}"),
        });
    }

    if field != "url" {
        return Err(if rest.is_empty() {
            ItemQueryError::UnknownField {
                field: field.to_string(),
            }
        } else {
            ItemQueryError::UnknownPath {
                path: query.to_string(),
            }
        });
    }

    if !rest.is_empty() {
        return Err(ItemQueryError::UnknownPath {
            path: query.to_string(),
        });
    }

    Ok(())
}

fn item_query_help(err: &ItemQueryError) -> String {
    match err {
        ItemQueryError::EmptySegment { .. } => "Use `${item}` for the whole repeated slot item or \
                                                `${item.url}` for the URL field."
            .to_string(),
        ItemQueryError::UnknownField { .. } | ItemQueryError::UnknownPath { .. } => {
            "Repeated slot items are objects like `{ url: ... }`. Use `${item}` for the whole \
             object or `${item.url}` for the URL field."
                .to_string()
        }
    }
}

fn validate_interpolated_string(
    value: &InterpolatedString,
    ctx: &SlotValidationContext<'_>,
    location: SlotLocation<'_>,
    span: SourceSpan,
    item_allowed: bool,
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

        if *kind == InterpolationSource::Item {
            if !item_allowed {
                diagnostics.push(Report::new(InvalidSlotsInterpolation {
                    component_path: ctx.component_path.to_string(),
                    location: location.label(),
                    message: "`item` interpolation is only valid inside repeated `each` expansions"
                        .to_string(),
                    help: "Move this interpolation inside a repeated `each` block and use \
                           `${item}` or `${item.url}` there."
                        .to_string(),
                    src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                        .with_language("json5"),
                    span,
                    label: "item interpolation here".to_string(),
                }));
                continue;
            }

            if let Err(err) = validate_item_query(query) {
                diagnostics.push(Report::new(InvalidSlotsInterpolation {
                    component_path: ctx.component_path.to_string(),
                    location: location.label(),
                    message: err.to_string(),
                    help: item_query_help(&err),
                    src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                        .with_language("json5"),
                    span,
                    label: "item interpolation here".to_string(),
                }));
            }
            continue;
        }

        if *kind != InterpolationSource::Slots {
            continue;
        }

        match parse_slot_query(query) {
            Ok(parsed) => match parsed.target {
                SlotTarget::All => {
                    if ctx.slots.values().any(|slot| slot.multiple) {
                        diagnostics.push(Report::new(InvalidSlotsInterpolation {
                            component_path: ctx.component_path.to_string(),
                            location: location.label(),
                            message: "`${slots}` cannot be used when the component declares \
                                      repeated slots"
                                .to_string(),
                            help: "Use `${slots.<slot>}` / `${slots.<slot>.url}` for singular \
                                   slots, and `each: \"slots.<slot>\"` with `${item}` or \
                                   `${item.url}` for repeated slots."
                                .to_string(),
                            src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                                .with_language("json5"),
                            span,
                            label: "slot interpolation here".to_string(),
                        }));
                    } else if ctx
                        .slots
                        .values()
                        .any(|slot_decl| slot_decl.decl.kind == CapabilityKind::Storage)
                    {
                        diagnostics.push(Report::new(InvalidSlotsInterpolation {
                            component_path: ctx.component_path.to_string(),
                            location: location.label(),
                            message: "storage slots are virtual storage objects and cannot be \
                                      interpolated through `${slots}`"
                                .to_string(),
                            help: "Reference a specific URL-shaped slot like `slots.api.url`, or \
                                   mount a storage slot with `program.mounts`."
                                .to_string(),
                            src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                                .with_language("json5"),
                            span,
                            label: "slot interpolation here".to_string(),
                        }));
                    }
                }
                SlotTarget::Slot(slot) => {
                    let Some(slot_decl) = ctx.slots.get(slot) else {
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
                        continue;
                    };

                    if slot_decl.decl.kind == CapabilityKind::Storage {
                        diagnostics.push(Report::new(InvalidSlotsInterpolation {
                            component_path: ctx.component_path.to_string(),
                            location: location.label(),
                            message: format!(
                                "storage slot `{slot}` is a virtual storage object, not a \
                                 URL-shaped slot"
                            ),
                            help: "Mount the storage slot with `program.mounts: [{ from: \
                                   \"slots.<slot>\", path: \"/var/lib/app\" }]` instead of using \
                                   `${slots...}`."
                                .to_string(),
                            src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                                .with_language("json5"),
                            span,
                            label: "slot interpolation here".to_string(),
                        }));
                        continue;
                    }

                    if slot_decl.multiple {
                        diagnostics.push(Report::new(InvalidSlotsInterpolation {
                            component_path: ctx.component_path.to_string(),
                            location: location.label(),
                            message: format!("slot `{slot}` is declared with `multiple: true`"),
                            help: format!(
                                "Use `each: \"slots.{slot}\"` with `${{item}}` or `${{item.url}}` \
                                 instead of `${{slots.{slot}...}}`."
                            ),
                            src: NamedSource::new(ctx.src_name, Arc::clone(ctx.source))
                                .with_language("json5"),
                            span,
                            label: "slot interpolation here".to_string(),
                        }));
                        continue;
                    }

                    if let Err(err) = validate_slot_query_for_slot(slot_decl, &parsed) {
                        let help = slot_query_help(Some(slot), &err);
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
            },
            Err(err) => {
                let help = slot_query_help(None, &err);
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

fn slot_query_help(slot: Option<&str>, err: &SlotQueryError) -> String {
    let whole_slot = slot.map_or_else(
        || "${slots.<slot>}".to_string(),
        |slot| format!("${{slots.{slot}}}"),
    );
    let slot_url = slot.map_or_else(
        || "${slots.<slot>.url}".to_string(),
        |slot| format!("${{slots.{slot}.url}}"),
    );

    match err {
        SlotQueryError::MissingSlotName => "Use `${slots.<slot>}` to refer to a slot object, then \
                                            continue with field paths as needed."
            .to_string(),
        SlotQueryError::EmptySegment { .. } => {
            format!("Use dot-separated slot paths like `{whole_slot}` or `{slot_url}`.")
        }
        SlotQueryError::UnknownField { .. } | SlotQueryError::UnknownPath { .. } => {
            let slot_shape = slot.map_or_else(
                || "Slots are objects like `{ url: ... }`.".to_string(),
                |slot| format!("Slot `{slot}` is an object like `{{ url: ... }}`."),
            );
            format!(
                "{slot_shape} Use `{whole_slot}` for the whole object or `{slot_url}` for the URL \
                 field."
            )
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
