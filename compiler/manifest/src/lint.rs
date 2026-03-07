#![allow(unused_assignments)]

use std::{collections::BTreeSet, sync::Arc};

use amber_config as rc;
use miette::{Diagnostic, NamedSource, SourceSpan};
use serde_json::Value;
use thiserror::Error;

use crate::{
    BindingSource, ComponentDecl, ExportTarget, InterpolatedPart, InterpolatedString,
    InterpolationSource, Manifest, ManifestSpans, MountSource, Program, ProgramArgItem, SlotName,
};

#[allow(unused_assignments)]
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
        "command argument references optional config `{path}` without `when_present` (in \
         component {component})"
    )]
    #[diagnostic(
        code(manifest::optional_command_config),
        severity(Warning),
        help(
            "Wrap the argument in `{{ when_present: \"config.{path}\", argv: [...] }}` if it \
             should disappear when unset, or make `config.{path}` required."
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
        "command `when_present` checks non-optional slot `{slot}`, so the condition is always \
         true (in component {component})"
    )]
    #[diagnostic(
        code(manifest::required_slot_when_present),
        severity(Warning),
        help(
            "Remove `when_present` if this argv group should always be included, or mark \
             `slots.{slot}` as `optional: true` if it should disappear when the slot is absent."
        )
    )]
    RequiredSlotWhenPresent {
        slot: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("non-optional slot condition")]
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
}

fn add_program_slot_uses<'a>(
    manifest: &'a Manifest,
    used_slots: &mut BTreeSet<&'a SlotName>,
    value: &InterpolatedString,
) -> bool {
    let used_all = value.visit_slot_uses(|slot_name| {
        if let Some((slot_key, _)) = manifest.slots().get_key_value(slot_name) {
            used_slots.insert(slot_key);
        }
    });
    if used_all {
        used_slots.extend(manifest.slots().keys());
    }
    used_all
}

fn add_slot_condition_use<'a>(
    manifest: &'a Manifest,
    used_slots: &mut BTreeSet<&'a SlotName>,
    query: &str,
) {
    if query.is_empty() {
        used_slots.extend(manifest.slots().keys());
        return;
    }
    let slot = slot_name_from_condition_query(query);
    if let Some((slot_key, _)) = manifest.slots().get_key_value(slot) {
        used_slots.insert(slot_key);
    }
}

fn slot_name_from_condition_query(query: &str) -> &str {
    query.split_once('.').map_or(query, |(first, _)| first)
}

fn visit_program_interpolated(
    program: &Program,
    mut visit: impl FnMut(&InterpolatedString) -> bool,
) -> bool {
    let executable = program.path_ref().or_else(|| program.image_ref());
    if let Some(executable) = executable
        && let Ok(parsed) = executable.parse::<InterpolatedString>()
        && visit(&parsed)
    {
        return true;
    }
    for item in &program.command().0 {
        match item {
            ProgramArgItem::Arg(arg) => {
                if visit(arg) {
                    return true;
                }
            }
            ProgramArgItem::Group(group) => {
                for arg in &group.argv.0 {
                    if visit(arg) {
                        return true;
                    }
                }
            }
        }
    }
    for value in program.env().values() {
        if visit(value) {
            return true;
        }
    }
    false
}

#[derive(Clone, Copy)]
enum CommandArgLintLocation {
    Entrypoint(usize),
    Args(usize),
}

impl CommandArgLintLocation {
    fn pointer(self) -> String {
        match self {
            Self::Entrypoint(idx) => format!("/program/entrypoint/{idx}"),
            Self::Args(idx) => format!("/program/args/{idx}"),
        }
    }
}

fn command_arg_optional_config_lints(
    manifest: &Manifest,
    component: &str,
    src: &NamedSource<Arc<str>>,
    spans: &ManifestSpans,
    optional_leaf_paths: &BTreeSet<String>,
) -> Vec<ManifestLint> {
    let Some(program) = manifest.program() else {
        return Vec::new();
    };

    let (items, location_of, field_pointer): (
        &[ProgramArgItem],
        fn(usize) -> CommandArgLintLocation,
        &str,
    ) = match program {
        Program::Image(program) => (
            &program.entrypoint.0,
            CommandArgLintLocation::Entrypoint,
            "/program/entrypoint",
        ),
        Program::Path(program) => (
            &program.args.0,
            CommandArgLintLocation::Args,
            "/program/args",
        ),
    };

    let source = src.inner().as_ref();
    let root = (0usize, source.len()).into();
    let fallback = spans
        .program
        .as_ref()
        .map(|program| program.whole)
        .unwrap_or((0usize, 0usize).into());

    let mut out = Vec::new();
    for (idx, item) in items.iter().enumerate() {
        match item {
            ProgramArgItem::Arg(arg) => {
                for part in &arg.parts {
                    let InterpolatedPart::Interpolation {
                        source: kind,
                        query,
                    } = part
                    else {
                        continue;
                    };
                    if *kind != InterpolationSource::Config || !optional_leaf_paths.contains(query)
                    {
                        continue;
                    }
                    let span =
                        crate::span_for_json_pointer(source, root, &location_of(idx).pointer())
                            .or_else(|| crate::span_for_json_pointer(source, root, field_pointer))
                            .unwrap_or(fallback);
                    out.push(ManifestLint::OptionalCommandConfig {
                        path: query.clone(),
                        component: component.to_string(),
                        src: src.clone(),
                        span,
                    });
                }
            }
            ProgramArgItem::Group(group) => {
                for (group_idx, arg) in group.argv.0.iter().enumerate() {
                    for part in &arg.parts {
                        let InterpolatedPart::Interpolation {
                            source: kind,
                            query,
                        } = part
                        else {
                            continue;
                        };
                        if *kind != InterpolationSource::Config
                            || !optional_leaf_paths.contains(query)
                            || (group.when_present.source() == InterpolationSource::Config
                                && query == group.when_present.query())
                        {
                            continue;
                        }
                        let pointer = format!("{}/{idx}/argv/{group_idx}", field_pointer);
                        let span = crate::span_for_json_pointer(source, root, &pointer)
                            .or_else(|| {
                                crate::span_for_json_pointer(
                                    source,
                                    root,
                                    &location_of(idx).pointer(),
                                )
                            })
                            .or_else(|| crate::span_for_json_pointer(source, root, field_pointer))
                            .unwrap_or(fallback);
                        out.push(ManifestLint::OptionalCommandConfig {
                            path: query.clone(),
                            component: component.to_string(),
                            src: src.clone(),
                            span,
                        });
                    }
                }
            }
        }
    }
    out
}

fn command_arg_required_slot_when_present_lints(
    manifest: &Manifest,
    component: &str,
    src: &NamedSource<Arc<str>>,
    spans: &ManifestSpans,
) -> Vec<ManifestLint> {
    let Some(program) = manifest.program() else {
        return Vec::new();
    };

    let (items, field_pointer): (&[ProgramArgItem], &str) = match program {
        Program::Image(program) => (&program.entrypoint.0, "/program/entrypoint"),
        Program::Path(program) => (&program.args.0, "/program/args"),
    };

    let source = src.inner().as_ref();
    let root = (0usize, source.len()).into();
    let fallback = spans
        .program
        .as_ref()
        .map(|program| program.whole)
        .unwrap_or((0usize, 0usize).into());

    let mut out = Vec::new();
    for (idx, item) in items.iter().enumerate() {
        let ProgramArgItem::Group(group) = item else {
            continue;
        };
        if group.when_present.source() != InterpolationSource::Slots {
            continue;
        }
        let slot = slot_name_from_condition_query(group.when_present.query());
        let Some(slot_decl) = manifest.slots().get(slot) else {
            continue;
        };
        if slot_decl.optional {
            continue;
        }

        let pointer = format!("{field_pointer}/{idx}/when_present");
        let item_pointer = format!("{field_pointer}/{idx}");
        let span = crate::span_for_json_pointer(source, root, &pointer)
            .or_else(|| crate::span_for_json_pointer(source, root, &item_pointer))
            .or_else(|| crate::span_for_json_pointer(source, root, field_pointer))
            .unwrap_or(fallback);
        out.push(ManifestLint::RequiredSlotWhenPresent {
            slot: slot.to_string(),
            component: component.to_string(),
            src: src.clone(),
            span,
        });
    }

    out
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

fn collect_config_uses(manifest: &Manifest) -> ConfigUses {
    let mut uses = ConfigUses::default();

    if let Some(program) = manifest.program() {
        for group in program.command().groups() {
            if group.when_present.source() == InterpolationSource::Config {
                uses.add_query(group.when_present.query());
            }
        }
        let _ = visit_program_interpolated(program, |value| {
            collect_config_uses_from_interpolated(value, &mut uses);
            false
        });
        for mount in program.mounts() {
            match &mount.source {
                MountSource::Config(path) | MountSource::Secret(path) => uses.add_query(path),
                MountSource::Slot(_) | MountSource::Binding(_) | MountSource::Framework(_) => {}
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
            for item in values {
                collect_config_uses_from_value(item, uses);
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

pub fn lint_manifest(
    manifest: &Manifest,
    component: &str,
    src: NamedSource<Arc<str>>,
    spans: &ManifestSpans,
) -> Vec<ManifestLint> {
    let mut lints = Vec::new();
    let component = component.to_string();

    let mut bound_slots = BTreeSet::new();
    let mut bound_provides = BTreeSet::new();
    for binding in manifest.bindings().values() {
        if let BindingSource::SelfProvide(provide_name) = &binding.from {
            bound_provides.insert(provide_name);
        }
        if let BindingSource::SelfSlot(slot_name) = &binding.from {
            bound_slots.insert(slot_name);
        }
    }

    let mut program_used_slots = BTreeSet::new();
    if let Some(program) = manifest.program() {
        for group in program.command().groups() {
            if group.when_present.source() == InterpolationSource::Slots {
                add_slot_condition_use(
                    manifest,
                    &mut program_used_slots,
                    group.when_present.query(),
                );
            }
        }
        let _ = visit_program_interpolated(program, |value| {
            add_program_slot_uses(manifest, &mut program_used_slots, value)
        });
    }

    let mut exported_provides = BTreeSet::new();
    let mut exported_slots = BTreeSet::new();
    for target in manifest.exports().values() {
        if let ExportTarget::SelfProvide(provide_name) = target {
            exported_provides.insert(provide_name);
        }
        if let ExportTarget::SelfSlot(slot_name) = target {
            exported_slots.insert(slot_name);
        }
    }

    if manifest.program().is_some() && bound_provides.is_empty() && exported_provides.is_empty() {
        let span = spans
            .program
            .as_ref()
            .map(|p| p.whole)
            .unwrap_or((0usize, 0usize).into());
        lints.push(ManifestLint::UnusedProgram {
            component: component.clone(),
            src: src.clone(),
            span,
        });
    }

    for (slot_name, slot_decl) in manifest.slots().iter() {
        if slot_decl.optional {
            continue;
        }
        if !bound_slots.contains(slot_name)
            && !program_used_slots.contains(slot_name)
            && !exported_slots.contains(slot_name)
        {
            let span = spans
                .slots
                .get(slot_name.as_str())
                .map(|s| s.name)
                .unwrap_or((0usize, 0usize).into());
            lints.push(ManifestLint::UnusedSlot {
                name: slot_name.to_string(),
                component: component.clone(),
                src: src.clone(),
                span,
            });
        }
    }

    for provide_name in manifest.provides().keys() {
        if !bound_provides.contains(provide_name) && !exported_provides.contains(provide_name) {
            let span = spans
                .provides
                .get(provide_name.as_str())
                .map(|p| p.capability.name)
                .unwrap_or((0usize, 0usize).into());
            lints.push(ManifestLint::UnusedProvide {
                name: provide_name.to_string(),
                component: component.clone(),
                src: src.clone(),
                span,
            });
        }
    }

    for (env_name, env) in manifest.environments() {
        let mut seen = BTreeSet::new();
        for (idx, resolver) in env.resolvers.iter().enumerate() {
            if !seen.insert(resolver.as_str()) {
                let span = spans
                    .environments
                    .get(env_name.as_str())
                    .and_then(|e| e.resolvers.get(idx).map(|(_, s)| *s))
                    .unwrap_or((0usize, 0usize).into());
                lints.push(ManifestLint::DuplicateEnvironmentResolver {
                    environment: env_name.clone(),
                    resolver: resolver.clone(),
                    component: component.clone(),
                    src: src.clone(),
                    span,
                });
            }
        }
    }

    if let Some(schema) = manifest.config_schema() {
        let config_uses = collect_config_uses(manifest);
        let schema_lints = rc::collect_schema_leaves(&schema.0);
        let optional_leaf_paths: BTreeSet<String> = schema_lints
            .leaves
            .iter()
            .filter(|leaf| !leaf.required)
            .map(|leaf| leaf.path.clone())
            .collect();

        if !schema_lints.unsupported.is_empty() {
            let mut reasons: Vec<_> = schema_lints.unsupported.into_iter().collect();
            reasons.sort();
            let reason = reasons.join(", ");
            let span = spans.config_schema.unwrap_or((0usize, 0usize).into());
            lints.push(ManifestLint::ConfigLintIncomplete {
                component: component.clone(),
                reason,
                src: src.clone(),
                span,
            });
        }

        let source = src.inner().as_ref();
        let schema_span = spans.config_schema.unwrap_or((0usize, 0usize).into());
        for leaf in schema_lints.leaves {
            if config_uses.is_used(&leaf.path) {
                continue;
            }
            let span = if leaf.pointer.is_empty() {
                schema_span
            } else {
                crate::span_for_json_pointer(source, schema_span, &leaf.pointer)
                    .unwrap_or(schema_span)
            };
            lints.push(ManifestLint::UnusedConfig {
                path: leaf.path,
                component: component.clone(),
                src: src.clone(),
                span,
            });
        }

        lints.extend(command_arg_optional_config_lints(
            manifest,
            &component,
            &src,
            spans,
            &optional_leaf_paths,
        ));
    }

    lints.extend(command_arg_required_slot_when_present_lints(
        manifest, &component, &src, spans,
    ));

    lints
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{Manifest, ManifestSpans, RawManifest};

    fn lint_for(input: &str, manifest: &Manifest) -> Vec<crate::lint::ManifestLint> {
        let source: Arc<str> = input.into();
        let spans = ManifestSpans::parse(&source);
        let src = miette::NamedSource::new("<test>", Arc::clone(&source)).with_language("json5");
        crate::lint::lint_manifest(manifest, "/", src, &spans)
    }

    fn parse_raw(input: &str) -> RawManifest {
        amber_json5::parse(input).unwrap()
    }

    #[test]
    fn environment_duplicate_resolvers_are_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          environments: {
            a: { resolvers: ["x", "x"] },
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::DuplicateEnvironmentResolver { environment, resolver, .. }
                if environment == "a" && resolver == "x"
        )));
    }

    #[test]
    fn unused_slot_is_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          slots: { llm: { kind: "llm" } },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedSlot { name, .. } if name == "llm"
        )));
    }

    #[test]
    fn unused_config_is_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              domain: { type: "string" },
              num_trials: { type: "integer" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["--domain", "${config.domain}"],
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedConfig { path, .. } if path == "num_trials"
        )));
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedConfig { path, .. } if path == "domain"
        )));
    }

    #[test]
    fn config_used_in_component_config_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              token: { type: "string" },
            },
          },
          components: {
            child: {
              manifest: "https://example.com/child",
              config: { token: "${config.token}" },
            },
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedConfig { path, .. } if path == "token"
        )));
    }

    #[test]
    fn config_lint_incomplete_is_reported() {
        let manifest = Manifest::builder()
            .config_schema(serde_json::json!({
                "type": "object",
                "properties": {
                    "loop": { "$ref": "#/properties/loop" },
                },
            }))
            .build()
            .unwrap();

        let input = r#"{ manifest_version: "0.1.0" }"#;
        let lints = lint_for(input, &manifest);
        assert!(
            lints
                .iter()
                .any(|lint| matches!(lint, crate::lint::ManifestLint::ConfigLintIncomplete { .. }))
        );
    }

    #[test]
    fn lint_manifest_handles_malformed_program_image_from_builder() {
        let program = crate::Program::image(
            crate::ProgramImage::builder()
                .image("${config.image")
                .entrypoint(crate::ProgramEntrypoint(vec![
                    "run".parse::<crate::InterpolatedString>().unwrap().into(),
                ]))
                .common(crate::ProgramCommon::default())
                .build(),
        );
        let manifest = Manifest::builder().program(program).build().unwrap();

        let input = r#"{ manifest_version: "0.1.0" }"#;
        let lints = lint_for(input, &manifest);
        assert!(
            lints
                .iter()
                .any(|lint| matches!(lint, crate::lint::ManifestLint::UnusedProgram { .. }))
        );
    }

    #[test]
    fn slot_used_in_program_entrypoint_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          slots: { llm: { kind: "llm" } },
          program: {
            image: "x",
            entrypoint: ["--llm", "${slots.llm.url}"],
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedSlot { name, .. } if name == "llm"
        )));
    }

    #[test]
    fn slot_used_in_program_env_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          slots: { llm: { kind: "llm" } },
          program: {
            image: "x",
            entrypoint: ["x"],
            env: { LLM_URL: "${slots.llm.url}" },
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedSlot { name, .. } if name == "llm"
        )));
    }

    #[test]
    fn slot_used_in_when_present_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          slots: { llm: { kind: "llm", optional: true } },
          program: {
            path: "/bin/echo",
            args: [
              {
                when_present: "slots.llm",
                argv: ["--llm", "${slots.llm.url}"],
              },
            ],
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedSlot { name, .. } if name == "llm"
        )));
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::RequiredSlotWhenPresent { slot, .. } if slot == "llm"
        )));
    }

    #[test]
    fn required_slot_when_present_is_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          slots: { llm: { kind: "llm" } },
          program: {
            image: "x",
            entrypoint: [
              {
                when_present: "slots.llm.url",
                argv: ["--llm", "${slots.llm.url}"],
              },
            ],
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::RequiredSlotWhenPresent { slot, .. } if slot == "llm"
        )));
    }

    #[test]
    fn optional_slot_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          slots: { llm: { kind: "llm", optional: true } },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedSlot { name, .. } if name == "llm"
        )));
    }

    #[test]
    fn unused_provide_is_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedProvide { name, .. } if name == "api"
        )));
    }

    #[test]
    fn unused_program_is_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          program: { image: "x", entrypoint: ["x"] },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(
            lints
                .iter()
                .any(|lint| matches!(lint, crate::lint::ManifestLint::UnusedProgram { .. }))
        );
    }

    #[test]
    fn program_used_by_binding_is_not_linted() {
        let input = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          components: {
            worker: "https://example.com/worker",
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
          bindings: [
            { to: "#worker.api", from: "self.api" },
          ],
        }
        "##;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(
            !lints
                .iter()
                .any(|lint| matches!(lint, crate::lint::ManifestLint::UnusedProgram { .. }))
        );
    }

    #[test]
    fn program_used_by_export_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "x",
            entrypoint: ["x"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
          exports: { api: "api" },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(
            !lints
                .iter()
                .any(|lint| matches!(lint, crate::lint::ManifestLint::UnusedProgram { .. }))
        );
    }

    #[test]
    fn exported_provide_is_not_linted() {
        let input = r#"
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
          exports: { public: "api" },
        }
        "#;
        let raw = parse_raw(input);

        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(lints.is_empty());
    }

    #[test]
    fn optional_command_config_is_linted_for_unguarded_args() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              profile: { type: "string" },
            },
          },
          program: {
            path: "/bin/echo",
            args: ["--profile", "${config.profile}"],
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::OptionalCommandConfig { path, .. } if path == "profile"
        )));
    }

    #[test]
    fn when_present_suppresses_matching_optional_command_lint_only() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              profile: { type: "string" },
              color: { type: "string" },
            },
          },
          program: {
            path: "/bin/echo",
            args: [
              {
                when_present: "config.profile",
                argv: ["--profile", "${config.profile}", "--color", "${config.color}"],
              },
            ],
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::OptionalCommandConfig { path, .. } if path == "profile"
        )));
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::OptionalCommandConfig { path, .. } if path == "color"
        )));
    }
}
