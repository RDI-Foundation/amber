#![allow(unused_assignments)]

use std::{collections::BTreeSet, sync::Arc};

use amber_config as rc;
use jsonptr::PointerBuf;
use miette::{Diagnostic, NamedSource, SourceSpan};
use serde_json::Value;
use thiserror::Error;

use crate::{
    BindingSource, ComponentDecl, ExportTarget, InterpolatedPart, InterpolatedString,
    InterpolationSource, Manifest, ManifestSpans, Program, ProgramArgValue, SlotTarget,
    parse_slot_query, validate_slot_query_for_slot,
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

    let Some((items, location_of, field_pointer)) = (match program {
        Program::Image(program) => Some((
            program.entrypoint.0.as_slice(),
            CommandArgLintLocation::Entrypoint as fn(usize) -> CommandArgLintLocation,
            "/program/entrypoint",
        )),
        Program::Path(program) => Some((
            program.args.0.as_slice(),
            CommandArgLintLocation::Args as fn(usize) -> CommandArgLintLocation,
            "/program/args",
        )),
        Program::Vm(_) => None,
    }) else {
        return Vec::new();
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
        let suppress_query = item
            .when()
            .filter(|when| when.source() == InterpolationSource::Config);
        let base_pointer = match &item.value {
            ProgramArgValue::Arg(_) => format!("{field_pointer}/{idx}/arg"),
            ProgramArgValue::Argv(_) => format!("{field_pointer}/{idx}/argv"),
        };
        item.visit_values(|arg| {
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
                    || suppress_query.is_some_and(|when| query == when.query())
                {
                    continue;
                }
                let span = crate::span_for_json_pointer(source, root, &base_pointer)
                    .or_else(|| {
                        crate::span_for_json_pointer(source, root, &location_of(idx).pointer())
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
        });
    }
    out
}

fn command_arg_required_slot_when_lints(
    manifest: &Manifest,
    component: &str,
    src: &NamedSource<Arc<str>>,
    spans: &ManifestSpans,
) -> Vec<ManifestLint> {
    let Some(program) = manifest.program() else {
        return Vec::new();
    };

    let Some((items, field_pointer)) = (match program {
        Program::Image(program) => Some((program.entrypoint.0.as_slice(), "/program/entrypoint")),
        Program::Path(program) => Some((program.args.0.as_slice(), "/program/args")),
        Program::Vm(_) => None,
    }) else {
        return Vec::new();
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
        let Some(when) = item.when() else {
            continue;
        };
        if when.source() != InterpolationSource::Slots {
            continue;
        }
        let Ok(parsed) = parse_slot_query(when.query()) else {
            continue;
        };
        let SlotTarget::Slot(slot) = parsed.target else {
            continue;
        };
        let Some(slot_decl) = manifest.slots().get(slot) else {
            continue;
        };
        let Ok(validation) = validate_slot_query_for_slot(slot_decl, &parsed) else {
            continue;
        };
        if slot_decl.optional || !validation.guaranteed_when_slot_is_bound {
            continue;
        }

        let pointer = format!("{field_pointer}/{idx}/when");
        let item_pointer = format!("{field_pointer}/{idx}");
        let span = crate::span_for_json_pointer(source, root, &pointer)
            .or_else(|| crate::span_for_json_pointer(source, root, &item_pointer))
            .or_else(|| crate::span_for_json_pointer(source, root, field_pointer))
            .unwrap_or(fallback);
        out.push(ManifestLint::RequiredSlotWhen {
            slot: slot.to_string(),
            component: component.to_string(),
            src: src.clone(),
            span,
        });
    }

    out
}

fn program_env_optional_config_lints(
    manifest: &Manifest,
    component: &str,
    src: &NamedSource<Arc<str>>,
    spans: &ManifestSpans,
    optional_leaf_paths: &BTreeSet<String>,
) -> Vec<ManifestLint> {
    let Some(program) = manifest.program() else {
        return Vec::new();
    };

    let source = src.inner().as_ref();
    let root = (0usize, source.len()).into();
    let fallback = spans
        .program
        .as_ref()
        .map(|program| program.whole)
        .unwrap_or((0usize, 0usize).into());

    let mut out = Vec::new();
    for (key, value) in program.env() {
        for part in &value.value().parts {
            let InterpolatedPart::Interpolation {
                source: kind,
                query,
            } = part
            else {
                continue;
            };
            if *kind != InterpolationSource::Config || !optional_leaf_paths.contains(query) {
                continue;
            }
            if let Some(when) = value.when()
                && when.source() == InterpolationSource::Config
                && query == when.query()
            {
                continue;
            }

            let pointer = if value.when().is_some() || value.each().is_some() {
                PointerBuf::from_tokens(["program", "env", key, "value"]).to_string()
            } else {
                PointerBuf::from_tokens(["program", "env", key]).to_string()
            };
            let span = crate::span_for_json_pointer(source, root, &pointer)
                .or_else(|| {
                    crate::span_for_json_pointer(
                        source,
                        root,
                        &PointerBuf::from_tokens(["program", "env", key]).to_string(),
                    )
                })
                .or_else(|| crate::span_for_json_pointer(source, root, "/program/env"))
                .unwrap_or(fallback);
            out.push(ManifestLint::OptionalEnvConfig {
                path: query.clone(),
                component: component.to_string(),
                src: src.clone(),
                span,
            });
        }
    }

    out
}

fn program_env_required_slot_when_lints(
    manifest: &Manifest,
    component: &str,
    src: &NamedSource<Arc<str>>,
    spans: &ManifestSpans,
) -> Vec<ManifestLint> {
    let Some(program) = manifest.program() else {
        return Vec::new();
    };

    let source = src.inner().as_ref();
    let root = (0usize, source.len()).into();
    let fallback = spans
        .program
        .as_ref()
        .map(|program| program.whole)
        .unwrap_or((0usize, 0usize).into());

    let mut out = Vec::new();
    for (key, value) in program.env() {
        let Some(when) = value.when() else {
            continue;
        };
        if when.source() != InterpolationSource::Slots {
            continue;
        }
        let Ok(parsed) = parse_slot_query(when.query()) else {
            continue;
        };
        let SlotTarget::Slot(slot) = parsed.target else {
            continue;
        };
        let Some(slot_decl) = manifest.slots().get(slot) else {
            continue;
        };
        let Ok(validation) = validate_slot_query_for_slot(slot_decl, &parsed) else {
            continue;
        };
        if slot_decl.optional || !validation.guaranteed_when_slot_is_bound {
            continue;
        }

        let pointer = PointerBuf::from_tokens(["program", "env", key, "when"]).to_string();
        let item_pointer = PointerBuf::from_tokens(["program", "env", key]).to_string();
        let span = crate::span_for_json_pointer(source, root, &pointer)
            .or_else(|| crate::span_for_json_pointer(source, root, &item_pointer))
            .or_else(|| crate::span_for_json_pointer(source, root, "/program/env"))
            .unwrap_or(fallback);
        out.push(ManifestLint::RequiredEnvSlotWhen {
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
        program.visit_config_uses(|_, query| uses.add_query(query));
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
    value.visit_config_uses(|query| uses.add_query(query));
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
    for binding in manifest.bindings() {
        if let BindingSource::SelfProvide(provide_name) = &binding.binding.from {
            bound_provides.insert(provide_name);
        }
        if let BindingSource::SelfSlot(slot_name) = &binding.binding.from {
            bound_slots.insert(slot_name);
        }
    }

    let mut program_used_slots = BTreeSet::new();
    if let Some(program) = manifest.program()
        && program.visit_slot_uses(|slot_name| {
            if let Some((slot_key, _)) = manifest.slots().get_key_value(slot_name) {
                program_used_slots.insert(slot_key);
            }
        })
    {
        program_used_slots.extend(manifest.slots().keys());
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
            .filter_map(
                |leaf| match rc::schema_path_presence(&schema.0, &leaf.path) {
                    Ok(rc::SchemaPresence::Present) => None,
                    Ok(rc::SchemaPresence::Absent | rc::SchemaPresence::Runtime) => {
                        Some(leaf.path.clone())
                    }
                    Err(_) => None,
                },
            )
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
        lints.extend(program_env_optional_config_lints(
            manifest,
            &component,
            &src,
            spans,
            &optional_leaf_paths,
        ));
    }

    lints.extend(command_arg_required_slot_when_lints(
        manifest, &component, &src, spans,
    ));
    lints.extend(program_env_required_slot_when_lints(
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
    fn config_used_only_by_vm_scalar_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              cpus: { type: "integer" },
              memory: { type: "integer" },
              other: { type: "string" }
            },
          },
          program: {
            vm: {
              image: "/tmp/base.qcow2",
              cpus: "${config.cpus}",
              memory_mib: "${config.memory}",
              network: {
                endpoints: [
                  { name: "http", port: 8080, protocol: "http" }
                ],
                egress: "none"
              }
            }
          },
          provides: {
            http: { kind: "http", endpoint: "http" }
          },
          exports: {
            http: "http"
          }
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedConfig { path, .. } if path == "cpus" || path == "memory"
        )));
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedConfig { path, .. } if path == "other"
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
    fn config_used_only_in_program_mounts_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_name: { type: "string" },
              mount_file: { type: "string" },
              source_path: { type: "string" },
              other: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [
              { path: "/etc/${config.mount_name}", from: "config.mount_file" },
              { path: "/tmp/value", from: "config.${config.source_path}" },
            ],
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedConfig { path, .. }
                if path == "mount_name" || path == "mount_file" || path == "source_path"
        )));
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedConfig { path, .. } if path == "other"
        )));
    }

    #[test]
    fn config_used_only_in_program_arg_each_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              items: {
                type: "array",
                items: { type: "string" },
              },
              other: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: [
              {
                each: "config.items",
                argv: ["${item}"],
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
            crate::lint::ManifestLint::UnusedConfig { path, .. } if path == "items"
        )));
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedConfig { path, .. } if path == "other"
        )));
    }

    #[test]
    fn config_used_only_in_program_endpoint_when_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              enabled: { type: "boolean" },
              other: { type: "string" },
            },
          },
          program: {
            image: "x",
            entrypoint: ["x"],
            network: {
              endpoints: [
                { when: "config.enabled", name: "http", port: 80 },
              ],
            },
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedConfig { path, .. } if path == "enabled"
        )));
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedConfig { path, .. } if path == "other"
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
    fn storage_slot_mounted_by_program_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          slots: { state: { kind: "storage" } },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [{ path: "/var/lib/app", from: "slots.state" }],
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedSlot { name, .. } if name == "state"
        )));
    }

    #[test]
    fn slot_used_only_in_program_mount_path_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              mount_file: { type: "string" },
            },
          },
          slots: { api: { kind: "http" } },
          program: {
            image: "x",
            entrypoint: ["x"],
            mounts: [{ path: "/tmp/${slots.api.url}", from: "config.mount_file" }],
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedSlot { name, .. } if name == "api"
        )));
    }

    #[test]
    fn slot_used_only_in_program_endpoint_when_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.3.0",
          slots: { api: { kind: "http" } },
          program: {
            image: "x",
            entrypoint: ["x"],
            network: {
              endpoints: [
                { when: "slots.api.url", name: "http", port: 80 },
              ],
            },
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedSlot { name, .. } if name == "api"
        )));
    }

    #[test]
    fn slot_used_in_when_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.2.0",
          slots: { llm: { kind: "llm", optional: true } },
          program: {
            path: "/bin/echo",
            args: [
              {
                when: "slots.llm.url",
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
            crate::lint::ManifestLint::RequiredSlotWhen { slot, .. } if slot == "llm"
        )));
    }

    #[test]
    fn required_slot_when_is_linted() {
        let input = r#"
        {
          manifest_version: "0.2.0",
          slots: { llm: { kind: "llm" } },
          program: {
            image: "x",
            entrypoint: [
              {
                when: "slots.llm",
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
            crate::lint::ManifestLint::RequiredSlotWhen { slot, .. } if slot == "llm"
        )));
    }

    #[test]
    fn required_slot_field_when_is_linted() {
        let input = r#"
        {
          manifest_version: "0.2.0",
          slots: { llm: { kind: "llm" } },
          program: {
            image: "x",
            entrypoint: [
              {
                when: "slots.llm.url",
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
            crate::lint::ManifestLint::RequiredSlotWhen { slot, .. } if slot == "llm"
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
    fn defaulted_command_config_is_not_linted_for_unguarded_args() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              profile: { type: "string", default: "dev" },
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
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::OptionalCommandConfig { path, .. } if path == "profile"
        )));
    }

    #[test]
    fn null_default_command_config_is_still_linted_for_unguarded_args() {
        let input = r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              profile: { type: ["string", "null"], default: null },
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
    fn when_suppresses_matching_optional_command_lint_only() {
        let input = r#"
        {
          manifest_version: "0.2.0",
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
                when: "config.profile",
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

    #[test]
    fn config_used_across_program_templates_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              command_each: { type: "array", items: { type: "string" } },
              command_name: { type: "string" },
              env_each: { type: "array", items: { type: "string" } },
              env_token: { type: "string" },
              endpoint_enabled: { type: "boolean" },
              endpoint_each: { type: "array", items: { type: "string" } },
              endpoint_name: { type: "string" },
              endpoint_port: { type: "string" },
              endpoint_protocol: { type: "string" },
              mount_enabled: { type: "boolean" },
              mount_each: { type: "array", items: { type: "string" } },
              mount_name: { type: "string" },
              mount_path: { type: "string" },
              mount_source: { type: "string" },
              unused: { type: "string" },
            },
          },
          program: {
            image: "app",
            entrypoint: [
              {
                each: "config.command_each",
                arg: "${config.command_name}",
              },
            ],
            env: {
              TOKEN: {
                each: "config.env_each",
                value: "${config.env_token}",
                join: ",",
              },
            },
            network: {
              endpoints: [
                {
                  when: "config.endpoint_enabled",
                  each: "config.endpoint_each",
                  name: "${config.endpoint_name}",
                  port: "${config.endpoint_port}",
                  protocol: "${config.endpoint_protocol}",
                },
              ],
            },
            mounts: [
              {
                when: "config.mount_enabled",
                each: "config.mount_each",
                name: "${config.mount_name}",
                path: "/tmp/${config.mount_path}",
                from: "config.${config.mount_source}",
              },
            ],
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);

        for used in [
            "command_each",
            "command_name",
            "env_each",
            "env_token",
            "endpoint_enabled",
            "endpoint_each",
            "endpoint_name",
            "endpoint_port",
            "endpoint_protocol",
            "mount_enabled",
            "mount_each",
            "mount_name",
            "mount_path",
            "mount_source",
        ] {
            assert!(
                !lints.iter().any(|lint| matches!(
                    lint,
                    crate::lint::ManifestLint::UnusedConfig { path, .. } if path == used
                )),
                "unexpected unused-config lint for {used}: {lints:#?}"
            );
        }
        assert!(lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedConfig { path, .. } if path == "unused"
        )));
    }

    #[test]
    fn slot_used_only_in_mount_template_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
          },
          slots: { api: { kind: "http" } },
          program: {
            image: "app",
            entrypoint: ["app"],
            mounts: [
              { path: "/tmp/${slots.api.url}", from: "config" },
            ],
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedSlot { name, .. } if name == "api"
        )));
    }

    #[test]
    fn slot_used_only_in_network_template_is_not_linted() {
        let input = r#"
        {
          manifest_version: "0.3.0",
          slots: { api: { kind: "http" } },
          program: {
            image: "app",
            entrypoint: ["app"],
            network: {
              endpoints: [
                { name: "${slots.api.url}", port: 8080, protocol: "http" },
              ],
            },
          },
        }
        "#;
        let raw = parse_raw(input);
        let manifest = raw.validate().unwrap();
        let lints = lint_for(input, &manifest);
        assert!(!lints.iter().any(|lint| matches!(
            lint,
            crate::lint::ManifestLint::UnusedSlot { name, .. } if name == "api"
        )));
    }
}
