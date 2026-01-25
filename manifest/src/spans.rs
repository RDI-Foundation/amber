use std::{collections::HashMap, sync::Arc};

pub use amber_json5::spans::span_for_json_pointer;
use amber_json5::spans::span_for_object_key;
use miette::SourceSpan;
use serde_json::{Map, Value};

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
    pub endpoints: Vec<EndpointSpans>,
}

#[derive(Clone, Debug)]
pub struct EndpointSpans {
    pub name: Arc<str>,
    pub whole: SourceSpan,
    pub name_span: SourceSpan,
    pub port_span: Option<SourceSpan>,
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
    pub name: Option<SourceSpan>,
    pub name_value: Option<Arc<str>>,
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
            name: None,
            name_value: None,
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

#[derive(Clone, Debug)]
struct SpanCursor<'a> {
    source: &'a str,
    span: SourceSpan,
}

impl<'a> SpanCursor<'a> {
    fn new(source: &'a str, span: SourceSpan) -> Self {
        Self { source, span }
    }

    fn child_span(&self, key: &str) -> Option<SourceSpan> {
        span_for_json_pointer(self.source, self.span, &pointer_for_key(key))
    }

    fn child_cursor(&self, key: &str) -> Option<Self> {
        Some(Self::new(self.source, self.child_span(key)?))
    }

    fn index_span(&self, index: usize) -> Option<SourceSpan> {
        span_for_json_pointer(self.source, self.span, &pointer_for_index(index))
    }

    fn index_cursor(&self, index: usize) -> Option<Self> {
        Some(Self::new(self.source, self.index_span(index)?))
    }
}

fn default_span() -> SourceSpan {
    (0usize, 0usize).into()
}

fn span_or_default(span: Option<SourceSpan>) -> SourceSpan {
    span.unwrap_or_else(default_span)
}

fn key_span(source: &str, object_span: SourceSpan, key: &str) -> SourceSpan {
    span_for_object_key(source, object_span, key).unwrap_or_else(default_span)
}

fn capability_decl_spans(
    root: &SpanCursor<'_>,
    section: &SpanCursor<'_>,
    name: &str,
    value: &Value,
) -> CapabilityDeclSpans {
    let name_span = key_span(root.source, section.span, name);
    let whole = span_or_default(section.child_span(name));
    let mut decl = CapabilityDeclSpans {
        name: name_span,
        whole,
        kind: None,
        profile: None,
    };

    if let Value::Object(obj) = value {
        let cursor = SpanCursor::new(root.source, whole);
        if obj.contains_key("kind") {
            decl.kind = cursor.child_span("kind");
        }
        if obj.contains_key("profile") {
            decl.profile = cursor.child_span("profile");
        }
    }

    decl
}

fn object_section<'a>(
    root: &SpanCursor<'a>,
    root_obj: &'a Map<String, Value>,
    key: &str,
) -> Option<(SpanCursor<'a>, &'a Map<String, Value>)> {
    let value = root_obj.get(key)?;
    let obj = value.as_object()?;
    let span = root.child_span(key)?;
    Some((SpanCursor::new(root.source, span), obj))
}

fn array_section<'a>(
    root: &SpanCursor<'a>,
    root_obj: &'a Map<String, Value>,
    key: &str,
) -> Option<(SpanCursor<'a>, &'a Vec<Value>)> {
    let value = root_obj.get(key)?;
    let array = value.as_array()?;
    let span = root.child_span(key)?;
    Some((SpanCursor::new(root.source, span), array))
}

pub(crate) fn parse_manifest_spans(source: &str) -> Option<ManifestSpans> {
    let root_value: Value = amber_json5::from_str(source).ok()?;
    let Some(root_obj) = root_value.as_object() else {
        return Some(ManifestSpans::default());
    };

    let root = SpanCursor::new(source, (0usize, source.len()).into());
    let mut out = ManifestSpans {
        manifest_version: root.child_span("manifest_version"),
        config_schema: root.child_span("config_schema"),
        ..ManifestSpans::default()
    };

    if let Some(program_value) = root_obj.get("program")
        && let Some(program) = root.child_cursor("program")
    {
        out.program = Some(extract_program_spans(program_value, program));
    }

    collect_components(&root, root_obj, &mut out);
    collect_environments(&root, root_obj, &mut out);
    collect_slots(&root, root_obj, &mut out);
    collect_provides(&root, root_obj, &mut out);
    collect_bindings(&root, root_obj, &mut out);
    collect_exports(&root, root_obj, &mut out);

    Some(out)
}

fn collect_components(
    root: &SpanCursor<'_>,
    root_obj: &Map<String, Value>,
    out: &mut ManifestSpans,
) {
    let Some((components, components_obj)) = object_section(root, root_obj, "components") else {
        return;
    };

    for (name, value) in components_obj {
        let name_span = key_span(root.source, components.span, name);
        let whole = span_or_default(components.child_span(name));
        let mut spans = ComponentDeclSpans {
            name: name_span,
            whole,
            manifest: None,
            environment: None,
            config: None,
        };

        match value {
            Value::String(_) => {
                spans.manifest = Some(whole);
            }
            Value::Object(obj) => {
                let component = SpanCursor::new(root.source, whole);
                if obj.contains_key("manifest") {
                    spans.manifest = component.child_span("manifest");
                }
                if obj.contains_key("environment") {
                    spans.environment = component.child_span("environment");
                }
                if obj.contains_key("config") {
                    spans.config = component.child_span("config");
                }
            }
            _ => {}
        }

        out.components.insert(name.as_str().into(), spans);
    }
}

fn collect_environments(
    root: &SpanCursor<'_>,
    root_obj: &Map<String, Value>,
    out: &mut ManifestSpans,
) {
    let Some((environments, environments_obj)) = object_section(root, root_obj, "environments")
    else {
        return;
    };

    for (env_name, env_value) in environments_obj {
        let name_span = key_span(root.source, environments.span, env_name);
        let whole = span_or_default(environments.child_span(env_name));
        let mut env_spans = EnvironmentSpans {
            name: name_span,
            whole,
            extends: None,
            resolvers: Vec::new(),
        };

        let Value::Object(env_obj) = env_value else {
            out.environments.insert(env_name.as_str().into(), env_spans);
            continue;
        };

        let env = SpanCursor::new(root.source, whole);
        if env_obj.contains_key("extends") {
            env_spans.extends = env.child_span("extends");
        }

        if let Some(resolvers) = env_obj.get("resolvers").and_then(Value::as_array)
            && let Some(resolver_list) = env.child_cursor("resolvers")
        {
            for (idx, resolver) in resolvers.iter().enumerate() {
                let Some(name) = resolver.as_str() else {
                    continue;
                };
                let Some(span) = resolver_list.index_span(idx) else {
                    continue;
                };
                env_spans.resolvers.push((name.into(), span));
            }
        }

        out.environments.insert(env_name.as_str().into(), env_spans);
    }
}

fn collect_slots(root: &SpanCursor<'_>, root_obj: &Map<String, Value>, out: &mut ManifestSpans) {
    let Some((slots, slots_obj)) = object_section(root, root_obj, "slots") else {
        return;
    };

    out.slots_section = Some(slots.span);

    for (slot_name, slot_value) in slots_obj {
        let decl = capability_decl_spans(root, &slots, slot_name, slot_value);
        out.slots.insert(slot_name.as_str().into(), decl);
    }
}

fn collect_provides(root: &SpanCursor<'_>, root_obj: &Map<String, Value>, out: &mut ManifestSpans) {
    let Some((provides, provides_obj)) = object_section(root, root_obj, "provides") else {
        return;
    };

    for (provide_name, provide_value) in provides_obj {
        let mut provide = ProvideDeclSpans {
            capability: capability_decl_spans(root, &provides, provide_name, provide_value),
            endpoint: None,
            endpoint_value: None,
        };

        if let Value::Object(obj) = provide_value {
            let decl = SpanCursor::new(root.source, provide.capability.whole);
            if let Some(endpoint) = obj.get("endpoint") {
                provide.endpoint = decl.child_span("endpoint");
                provide.endpoint_value = endpoint.as_str().map(Into::into);
            }
        }

        out.provides.insert(provide_name.as_str().into(), provide);
    }
}

fn collect_bindings(root: &SpanCursor<'_>, root_obj: &Map<String, Value>, out: &mut ManifestSpans) {
    let Some((bindings, bindings_array)) = array_section(root, root_obj, "bindings") else {
        return;
    };

    for (idx, binding_value) in bindings_array.iter().enumerate() {
        let whole = span_or_default(bindings.index_span(idx));
        let mut spans = BindingSpans {
            whole,
            ..BindingSpans::default()
        };

        let Value::Object(fields) = binding_value else {
            out.bindings_by_index.push(spans);
            continue;
        };

        let binding = SpanCursor::new(root.source, whole);
        let span_for = |key: &str| {
            fields
                .contains_key(key)
                .then(|| binding.child_span(key))
                .flatten()
        };
        let get_string = |key: &str| fields.get(key).and_then(|v| v.as_str()).map(Into::into);

        spans.to = span_for("to");
        spans.to_value = get_string("to");

        spans.name = span_for("name");
        spans.name_value = get_string("name");

        spans.from = span_for("from");
        spans.from_value = get_string("from");

        spans.slot = span_for("slot");
        spans.slot_value = get_string("slot");

        spans.capability = span_for("capability");
        spans.capability_value = get_string("capability");

        spans.weak = span_for("weak");

        if let Some(to) = spans.to_value.as_deref() {
            let slot = spans.slot_value.as_deref();
            if let Some(key) = crate::binding_target_key_for_binding(to, slot) {
                out.bindings.insert(key, spans.clone());
            }
        }

        out.bindings_by_index.push(spans);
    }
}

fn collect_exports(root: &SpanCursor<'_>, root_obj: &Map<String, Value>, out: &mut ManifestSpans) {
    let Some((exports, exports_obj)) = object_section(root, root_obj, "exports") else {
        return;
    };

    for (export_name, _export_value) in exports_obj {
        let name_span = key_span(root.source, exports.span, export_name);
        let target = span_or_default(exports.child_span(export_name));
        out.exports.insert(
            export_name.as_str().into(),
            ExportSpans {
                name: name_span,
                target,
            },
        );
    }
}

impl ManifestSpans {
    /// Best-effort span extraction for a manifest JSON5 document.
    ///
    /// If parsing fails, this returns an empty span set.
    pub fn parse(source: &str) -> Self {
        parse_manifest_spans(source).unwrap_or_default()
    }
}

fn extract_program_spans(program_value: &Value, program: SpanCursor<'_>) -> ProgramSpans {
    let mut endpoints = Vec::new();
    let whole = program.span;
    let Some(program_obj) = program_value.as_object() else {
        return ProgramSpans { whole, endpoints };
    };
    let Some(network) = program_obj.get("network") else {
        return ProgramSpans { whole, endpoints };
    };
    let Some(endpoint_array) = network.get("endpoints").and_then(Value::as_array) else {
        return ProgramSpans { whole, endpoints };
    };
    let Some(network) = program.child_cursor("network") else {
        return ProgramSpans { whole, endpoints };
    };
    let Some(endpoints_span) = network.child_cursor("endpoints") else {
        return ProgramSpans { whole, endpoints };
    };

    for (idx, endpoint) in endpoint_array.iter().enumerate() {
        let Some(name) = endpoint.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(endpoint_span) = endpoints_span.index_cursor(idx) else {
            continue;
        };
        let Some(name_span) = endpoint_span.child_span("name") else {
            continue;
        };
        endpoints.push(EndpointSpans {
            name: name.into(),
            whole: endpoint_span.span,
            name_span,
            port_span: endpoint_span.child_span("port"),
        });
    }

    ProgramSpans { whole, endpoints }
}

fn pointer_for_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 1);
    out.push('/');
    push_json_pointer_segment(&mut out, key);
    out
}

fn pointer_for_index(index: usize) -> String {
    let mut out = String::new();
    out.push('/');
    use std::fmt::Write as _;
    let _ = write!(out, "{index}");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn span_text(source: &str, span: SourceSpan) -> &str {
        let start = span.offset();
        let end = start + span.len();
        source.get(start..end).expect("span within source")
    }

    #[test]
    fn span_for_json_pointer_finds_nested_values() {
        let source = r#"{ foo: { bar: 42, list: ["a", "b"] } }"#;
        let root: SourceSpan = (0usize, source.len()).into();

        let bar = span_for_json_pointer(source, root, "/foo/bar").unwrap();
        assert_eq!(span_text(source, bar).trim(), "42");

        let list_1 = span_for_json_pointer(source, root, "/foo/list/1").unwrap();
        assert_eq!(span_text(source, list_1).trim(), "\"b\"");
    }

    #[test]
    fn span_for_json_pointer_unescapes_segments() {
        let source = r#"{ "~": { "/": 1 } }"#;
        let root: SourceSpan = (0usize, source.len()).into();

        let span = span_for_json_pointer(source, root, "/~0/~1").unwrap();
        assert_eq!(span_text(source, span).trim(), "1");
    }

    #[test]
    fn manifest_spans_capture_program_endpoint_names() {
        let source = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "example",
            network: {
              endpoints: [
                { name: "http", port: 80 },
                { name: "admin", port: 8080 },
              ],
            },
          },
        }
        "#;
        let spans = ManifestSpans::parse(source);
        let program = spans.program.expect("program spans");

        let http_span = program
            .endpoints
            .iter()
            .find(|endpoint| endpoint.name.as_ref() == "http")
            .map(|endpoint| endpoint.name_span)
            .expect("http endpoint span");
        assert_eq!(span_text(source, http_span), "\"http\"");

        let admin_span = program
            .endpoints
            .iter()
            .find(|endpoint| endpoint.name.as_ref() == "admin")
            .map(|endpoint| endpoint.name_span)
            .expect("admin endpoint span");
        assert_eq!(span_text(source, admin_span), "\"admin\"");
    }
}
