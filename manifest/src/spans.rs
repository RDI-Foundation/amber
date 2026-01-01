use std::{collections::HashMap, sync::Arc};

pub use amber_json5::spans::span_for_json_pointer;
use amber_json5::spans::span_for_object_key;
use miette::SourceSpan;

#[derive(Clone, Debug, Default)]
pub struct ManifestSpans {
    pub manifest_version: Option<SourceSpan>,
    pub program: Option<ProgramSpans>,
    pub config_schema: Option<SourceSpan>,
    pub components: HashMap<Arc<str>, ComponentDeclSpans>,
    pub environments: HashMap<Arc<str>, EnvironmentSpans>,
    pub slots: HashMap<Arc<str>, CapabilityDeclSpans>,
    pub slots_section: Option<SourceSpan>,
    pub provides: HashMap<Arc<str>, ProvideDeclSpans>,
    pub bindings: HashMap<BindingTargetKey, BindingSpans>,
    pub bindings_by_index: Vec<BindingSpans>,
    pub exports: HashMap<Arc<str>, ExportSpans>,
}

#[derive(Clone, Debug)]
pub struct ProgramSpans {
    pub whole: SourceSpan,
    pub endpoints: Vec<(Arc<str>, SourceSpan)>,
}

#[derive(Clone, Debug)]
pub struct ComponentDeclSpans {
    pub name: SourceSpan,
    pub whole: SourceSpan,
    pub manifest: Option<SourceSpan>,
    pub environment: Option<SourceSpan>,
    pub config: Option<SourceSpan>,
}

#[derive(Clone, Debug)]
pub struct EnvironmentSpans {
    pub name: SourceSpan,
    pub whole: SourceSpan,
    pub extends: Option<SourceSpan>,
    pub resolvers: Vec<(Arc<str>, SourceSpan)>,
}

#[derive(Clone, Debug)]
pub struct CapabilityDeclSpans {
    pub name: SourceSpan,
    pub whole: SourceSpan,
    pub kind: Option<SourceSpan>,
    pub profile: Option<SourceSpan>,
}

#[derive(Clone, Debug)]
pub struct ProvideDeclSpans {
    pub capability: CapabilityDeclSpans,
    pub endpoint: Option<SourceSpan>,
    pub endpoint_value: Option<Arc<str>>,
}

#[derive(Clone, Debug)]
pub struct ExportSpans {
    pub name: SourceSpan,
    pub target: SourceSpan,
}

#[derive(Clone, Debug)]
pub struct BindingSpans {
    pub whole: SourceSpan,
    pub to: Option<SourceSpan>,
    pub to_value: Option<Arc<str>>,
    pub from: Option<SourceSpan>,
    pub from_value: Option<Arc<str>>,
    pub slot: Option<SourceSpan>,
    pub slot_value: Option<Arc<str>>,
    pub capability: Option<SourceSpan>,
    pub capability_value: Option<Arc<str>>,
    pub weak: Option<SourceSpan>,
}

impl Default for BindingSpans {
    fn default() -> Self {
        Self {
            whole: (0usize, 0usize).into(),
            to: None,
            to_value: None,
            from: None,
            from_value: None,
            slot: None,
            slot_value: None,
            capability: None,
            capability_value: None,
            weak: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BindingTargetKey {
    SelfSlot(Arc<str>),
    ChildSlot { child: Arc<str>, slot: Arc<str> },
}

impl From<&super::BindingTarget> for BindingTargetKey {
    fn from(value: &super::BindingTarget) -> Self {
        match value {
            super::BindingTarget::SelfSlot(slot) => Self::SelfSlot(slot.as_str().into()),
            super::BindingTarget::ChildSlot { child, slot } => Self::ChildSlot {
                child: child.as_str().into(),
                slot: slot.as_str().into(),
            },
        }
    }
}

impl BindingTargetKey {
    pub fn slot(&self) -> &str {
        match self {
            Self::SelfSlot(slot) => slot,
            Self::ChildSlot { slot, .. } => slot,
        }
    }
}

pub(crate) fn parse_manifest_spans(source: &str) -> Option<ManifestSpans> {
    let root_value: serde_json::Value = amber_json5::from_str(source).ok()?;
    let Some(root_obj) = root_value.as_object() else {
        return Some(ManifestSpans::default());
    };

    let root_span: SourceSpan = (0usize, source.len()).into();
    let mut out = ManifestSpans {
        manifest_version: span_for_json_pointer(source, root_span, "/manifest_version"),
        config_schema: span_for_json_pointer(source, root_span, "/config_schema"),
        ..ManifestSpans::default()
    };

    if root_obj.get("program").is_some()
        && let Some(whole) = span_for_json_pointer(source, root_span, "/program")
    {
        out.program = Some(extract_program_spans(source, root_span, whole, root_obj));
    }

    if let Some(components_value) = root_obj.get("components")
        && let Some(components_obj) = components_value.as_object()
        && let Some(components_span) = span_for_json_pointer(source, root_span, "/components")
    {
        for (name, value) in components_obj {
            let name_span = span_for_object_key(source, components_span, name)
                .unwrap_or((0usize, 0usize).into());
            let value_span =
                span_for_json_pointer(source, root_span, &pointer(["components", name]))
                    .unwrap_or((0usize, 0usize).into());

            let mut spans = ComponentDeclSpans {
                name: name_span,
                whole: value_span,
                manifest: None,
                environment: None,
                config: None,
            };

            match value {
                serde_json::Value::String(_) => {
                    spans.manifest = Some(value_span);
                }
                serde_json::Value::Object(obj) => {
                    spans.manifest = obj.get("manifest").and_then(|_| {
                        span_for_json_pointer(
                            source,
                            root_span,
                            &pointer(["components", name, "manifest"]),
                        )
                    });
                    spans.environment = obj.get("environment").and_then(|_| {
                        span_for_json_pointer(
                            source,
                            root_span,
                            &pointer(["components", name, "environment"]),
                        )
                    });
                    spans.config = obj.get("config").and_then(|_| {
                        span_for_json_pointer(
                            source,
                            root_span,
                            &pointer(["components", name, "config"]),
                        )
                    });
                }
                _ => {}
            }

            out.components.insert(name.as_str().into(), spans);
        }
    }

    if let Some(environments_value) = root_obj.get("environments")
        && let Some(environments_obj) = environments_value.as_object()
        && let Some(environments_span) = span_for_json_pointer(source, root_span, "/environments")
    {
        for (env_name, env_value) in environments_obj {
            let env_name_span = span_for_object_key(source, environments_span, env_name)
                .unwrap_or((0usize, 0usize).into());
            let env_whole =
                span_for_json_pointer(source, root_span, &pointer(["environments", env_name]))
                    .unwrap_or((0usize, 0usize).into());

            let mut env_spans = EnvironmentSpans {
                name: env_name_span,
                whole: env_whole,
                extends: None,
                resolvers: Vec::new(),
            };

            if let serde_json::Value::Object(env_obj) = env_value {
                env_spans.extends = env_obj.get("extends").and_then(|_| {
                    span_for_json_pointer(
                        source,
                        root_span,
                        &pointer(["environments", env_name, "extends"]),
                    )
                });

                if let Some(resolvers) = env_obj.get("resolvers").and_then(|v| v.as_array()) {
                    env_spans.resolvers = resolvers
                        .iter()
                        .enumerate()
                        .filter_map(|(i, v)| {
                            let s = v.as_str()?;
                            let span = span_for_json_pointer(
                                source,
                                root_span,
                                &pointer(["environments", env_name, "resolvers", &i.to_string()]),
                            )?;
                            Some((s.into(), span))
                        })
                        .collect();
                }
            }

            out.environments.insert(env_name.as_str().into(), env_spans);
        }
    }

    if let Some(slots_value) = root_obj.get("slots")
        && let Some(slots_obj) = slots_value.as_object()
        && let Some(slots_span) = span_for_json_pointer(source, root_span, "/slots")
    {
        out.slots_section = Some(slots_span);

        for (slot_name, slot_value) in slots_obj {
            let slot_name_span = span_for_object_key(source, slots_span, slot_name)
                .unwrap_or((0usize, 0usize).into());
            let whole = span_for_json_pointer(source, root_span, &pointer(["slots", slot_name]))
                .unwrap_or((0usize, 0usize).into());

            let mut decl = CapabilityDeclSpans {
                name: slot_name_span,
                whole,
                kind: None,
                profile: None,
            };

            if let serde_json::Value::Object(obj) = slot_value {
                decl.kind = obj.get("kind").and_then(|_| {
                    span_for_json_pointer(source, root_span, &pointer(["slots", slot_name, "kind"]))
                });
                decl.profile = obj.get("profile").and_then(|_| {
                    span_for_json_pointer(
                        source,
                        root_span,
                        &pointer(["slots", slot_name, "profile"]),
                    )
                });
            }

            out.slots.insert(slot_name.as_str().into(), decl);
        }
    }

    if let Some(provides_value) = root_obj.get("provides")
        && let Some(provides_obj) = provides_value.as_object()
        && let Some(provides_span) = span_for_json_pointer(source, root_span, "/provides")
    {
        for (provide_name, provide_value) in provides_obj {
            let provide_name_span = span_for_object_key(source, provides_span, provide_name)
                .unwrap_or((0usize, 0usize).into());
            let whole =
                span_for_json_pointer(source, root_span, &pointer(["provides", provide_name]))
                    .unwrap_or((0usize, 0usize).into());

            let mut provide = ProvideDeclSpans {
                capability: CapabilityDeclSpans {
                    name: provide_name_span,
                    whole,
                    kind: None,
                    profile: None,
                },
                endpoint: None,
                endpoint_value: None,
            };

            if let serde_json::Value::Object(obj) = provide_value {
                provide.capability.kind = obj.get("kind").and_then(|_| {
                    span_for_json_pointer(
                        source,
                        root_span,
                        &pointer(["provides", provide_name, "kind"]),
                    )
                });
                provide.capability.profile = obj.get("profile").and_then(|_| {
                    span_for_json_pointer(
                        source,
                        root_span,
                        &pointer(["provides", provide_name, "profile"]),
                    )
                });

                if let Some(endpoint) = obj.get("endpoint") {
                    provide.endpoint = span_for_json_pointer(
                        source,
                        root_span,
                        &pointer(["provides", provide_name, "endpoint"]),
                    );
                    provide.endpoint_value = endpoint.as_str().map(Into::into);
                }
            }

            out.provides.insert(provide_name.as_str().into(), provide);
        }
    }

    if let Some(bindings_value) = root_obj.get("bindings")
        && let Some(bindings_array) = bindings_value.as_array()
    {
        for (idx, binding_value) in bindings_array.iter().enumerate() {
            let whole =
                span_for_json_pointer(source, root_span, &pointer(["bindings", &idx.to_string()]))
                    .unwrap_or((0usize, 0usize).into());

            let mut spans = BindingSpans {
                whole,
                ..BindingSpans::default()
            };

            let serde_json::Value::Object(fields) = binding_value else {
                out.bindings_by_index.push(spans);
                continue;
            };

            let get_string = |k: &str| fields.get(k).and_then(|v| v.as_str()).map(Into::into);

            spans.to = fields.get("to").and_then(|_| {
                span_for_json_pointer(
                    source,
                    root_span,
                    &pointer(["bindings", &idx.to_string(), "to"]),
                )
            });
            spans.to_value = get_string("to");

            spans.from = fields.get("from").and_then(|_| {
                span_for_json_pointer(
                    source,
                    root_span,
                    &pointer(["bindings", &idx.to_string(), "from"]),
                )
            });
            spans.from_value = get_string("from");

            spans.slot = fields.get("slot").and_then(|_| {
                span_for_json_pointer(
                    source,
                    root_span,
                    &pointer(["bindings", &idx.to_string(), "slot"]),
                )
            });
            spans.slot_value = get_string("slot");

            spans.capability = fields.get("capability").and_then(|_| {
                span_for_json_pointer(
                    source,
                    root_span,
                    &pointer(["bindings", &idx.to_string(), "capability"]),
                )
            });
            spans.capability_value = get_string("capability");

            spans.weak = fields.get("weak").and_then(|_| {
                span_for_json_pointer(
                    source,
                    root_span,
                    &pointer(["bindings", &idx.to_string(), "weak"]),
                )
            });

            if let Some(to) = spans.to_value.as_deref() {
                let slot = spans.slot_value.as_deref();
                if let Some(key) = crate::binding_target_key_for_binding(to, slot) {
                    out.bindings.insert(key, spans.clone());
                }
            }

            out.bindings_by_index.push(spans);
        }
    }

    if let Some(exports_value) = root_obj.get("exports")
        && let Some(exports_obj) = exports_value.as_object()
        && let Some(exports_span) = span_for_json_pointer(source, root_span, "/exports")
    {
        for (export_name, _export_value) in exports_obj {
            let name_span = span_for_object_key(source, exports_span, export_name)
                .unwrap_or((0usize, 0usize).into());
            let target =
                span_for_json_pointer(source, root_span, &pointer(["exports", export_name]))
                    .unwrap_or((0usize, 0usize).into());
            out.exports.insert(
                export_name.as_str().into(),
                ExportSpans {
                    name: name_span,
                    target,
                },
            );
        }
    }

    Some(out)
}

impl ManifestSpans {
    /// Best-effort span extraction for a manifest JSON5 document.
    ///
    /// If parsing fails, this returns an empty span set.
    pub fn parse(source: &str) -> Self {
        parse_manifest_spans(source).unwrap_or_default()
    }
}

fn extract_program_spans(
    source: &str,
    root_span: SourceSpan,
    whole: SourceSpan,
    root_obj: &serde_json::Map<String, serde_json::Value>,
) -> ProgramSpans {
    let mut endpoints = Vec::new();
    let Some(program) = root_obj.get("program") else {
        return ProgramSpans { whole, endpoints };
    };
    let Some(network) = program.get("network") else {
        return ProgramSpans { whole, endpoints };
    };
    let Some(endpoint_array) = network.get("endpoints").and_then(|v| v.as_array()) else {
        return ProgramSpans { whole, endpoints };
    };

    for (idx, endpoint) in endpoint_array.iter().enumerate() {
        let Some(name) = endpoint.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(span) = span_for_json_pointer(
            source,
            root_span,
            &pointer(["program", "network", "endpoints", &idx.to_string(), "name"]),
        ) else {
            continue;
        };
        endpoints.push((name.into(), span));
    }

    ProgramSpans { whole, endpoints }
}

fn pointer<const N: usize>(segments: [&str; N]) -> String {
    let mut out = String::new();
    for segment in segments {
        out.push('/');
        push_json_pointer_segment(&mut out, segment);
    }
    out
}

fn push_json_pointer_segment(out: &mut String, segment: &str) {
    for c in segment.chars() {
        match c {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            other => out.push(other),
        }
    }
}
