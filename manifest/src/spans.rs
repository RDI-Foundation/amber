use std::{borrow::Cow, collections::HashMap, sync::Arc};

use miette::SourceSpan;
use pest::Parser as _;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "json5.pest"]
struct Json5Parser;

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
    let mut pairs = Json5Parser::parse(Rule::text, source).ok()?;
    let root = pairs.next()?;
    if root.as_rule() != Rule::object {
        return Some(ManifestSpans::default());
    }

    let mut out = ManifestSpans::default();
    for (key, key_span, value) in object_fields(root) {
        match key.as_ref() {
            "manifest_version" => out.manifest_version = Some(span(&value)),
            "program" => out.program = Some(extract_program(value)),
            "config_schema" => out.config_schema = Some(span(&value)),
            "components" => extract_components(&mut out, value),
            "environments" => extract_environments(&mut out, value),
            "slots" => {
                out.slots_section = Some(span(&value));
                extract_slots(&mut out, value);
            }
            "provides" => extract_provides(&mut out, value),
            "bindings" => extract_bindings(&mut out, value),
            "exports" => extract_exports(&mut out, value),
            _ => {}
        }

        // Keep lint spans stable even if key is ignored.
        let _ = key_span;
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

/// Find the `SourceSpan` for a JSON Pointer within a JSON5 value span.
///
/// This is intended for diagnostics: given a span of a value (typically an object like a
/// `config: { ... }` block) and a JSON Pointer (like `/foo/0/bar`), returns the span of the
/// referenced value.
pub fn span_for_json_pointer(
    source: &str,
    value_span: SourceSpan,
    pointer: &str,
) -> Option<SourceSpan> {
    let value_start = value_span.offset();
    let value_end = span_end(value_span);
    let value_src = source.get(value_start..value_end)?;

    let mut pairs = Json5Parser::parse(Rule::text, value_src).ok()?;
    let mut current = pairs.next()?;
    let mut out = shift_span(span(&current), value_start);

    for segment in pointer.split('/').filter(|s| !s.is_empty()) {
        let segment = unescape_json_pointer_segment(segment);
        match current.as_rule() {
            Rule::object => {
                let mut found = None;
                for (key, _key_span, value) in object_fields(current.clone()) {
                    if key.as_ref() == segment.as_ref() {
                        found = Some(value);
                        break;
                    }
                }
                let value = found?;
                out = shift_span(span(&value), value_start);
                current = value;
            }
            Rule::array => {
                let index = segment.parse::<usize>().ok()?;
                let value = current.clone().into_inner().nth(index)?;
                out = shift_span(span(&value), value_start);
                current = value;
            }
            _ => return None,
        }
    }

    Some(out)
}

pub(crate) fn span_for_object_key(
    source: &str,
    object_span: SourceSpan,
    key: &str,
) -> Option<SourceSpan> {
    let value_start = object_span.offset();
    let value_end = span_end(object_span);
    let value_src = source.get(value_start..value_end)?;

    let mut pairs = Json5Parser::parse(Rule::text, value_src).ok()?;
    let object = pairs.next()?;
    if object.as_rule() != Rule::object {
        return None;
    }

    for (field, field_span, _value) in object_fields(object) {
        if field.as_ref() == key {
            return Some(shift_span(field_span, value_start));
        }
    }

    None
}

fn extract_components(out: &mut ManifestSpans, value: pest::iterators::Pair<'_, Rule>) {
    if value.as_rule() != Rule::object {
        return;
    }
    for (name, name_span, value) in object_fields(value) {
        let spans = extract_component_decl(name_span, value);
        out.components.insert(name, spans);
    }
}

fn extract_component_decl(
    name: SourceSpan,
    value: pest::iterators::Pair<'_, Rule>,
) -> ComponentDeclSpans {
    let whole = span(&value);
    let mut out = ComponentDeclSpans {
        name,
        whole,
        manifest: None,
        environment: None,
        config: None,
    };

    match value.as_rule() {
        Rule::string => {
            out.manifest = Some(span(&value));
        }
        Rule::object => {
            for (k, _k_span, v) in object_fields(value) {
                match k.as_ref() {
                    "manifest" => out.manifest = Some(span(&v)),
                    "environment" => out.environment = Some(span(&v)),
                    "config" => out.config = Some(span(&v)),
                    _ => {}
                }
            }
        }
        _ => {}
    }

    out
}

fn extract_program(value: pest::iterators::Pair<'_, Rule>) -> ProgramSpans {
    let whole = span(&value);
    if value.as_rule() != Rule::object {
        return ProgramSpans {
            whole,
            endpoints: Vec::new(),
        };
    }

    let mut endpoints = Vec::new();
    for (k, _k_span, v) in object_fields(value) {
        if k.as_ref() != "network" || v.as_rule() != Rule::object {
            continue;
        }

        for (nk, _nk_span, nv) in object_fields(v) {
            if nk.as_ref() != "endpoints" || nv.as_rule() != Rule::array {
                continue;
            }

            for ep in nv.into_inner() {
                if ep.as_rule() != Rule::object {
                    continue;
                }

                for (ek, _ek_span, ev) in object_fields(ep) {
                    if ek.as_ref() != "name" {
                        continue;
                    }
                    if let Some(name) = string_value(&ev) {
                        endpoints.push((name.into(), span(&ev)));
                    }
                    break;
                }
            }
        }
    }

    ProgramSpans { whole, endpoints }
}

fn extract_environments(out: &mut ManifestSpans, value: pest::iterators::Pair<'_, Rule>) {
    if value.as_rule() != Rule::object {
        return;
    }
    for (env_name, env_name_span, env_val) in object_fields(value) {
        if env_val.as_rule() != Rule::object {
            continue;
        }
        let whole = span(&env_val);
        let mut env_spans = EnvironmentSpans {
            name: env_name_span,
            whole,
            extends: None,
            resolvers: Vec::new(),
        };

        for (k, _k_span, v) in object_fields(env_val) {
            match k.as_ref() {
                "extends" => env_spans.extends = Some(span(&v)),
                "resolvers" => env_spans.resolvers = array_string_items(v),
                _ => {}
            }
        }

        out.environments.insert(env_name, env_spans);
    }
}

fn extract_slots(out: &mut ManifestSpans, value: pest::iterators::Pair<'_, Rule>) {
    if value.as_rule() != Rule::object {
        return;
    }
    for (slot_name, slot_name_span, slot_val) in object_fields(value) {
        let decl = extract_capability_decl(slot_name_span, slot_val);
        out.slots.insert(slot_name, decl);
    }
}

fn extract_provides(out: &mut ManifestSpans, value: pest::iterators::Pair<'_, Rule>) {
    if value.as_rule() != Rule::object {
        return;
    }
    for (provide_name, provide_name_span, provide_val) in object_fields(value) {
        let mut provide = ProvideDeclSpans {
            capability: extract_capability_decl(provide_name_span, provide_val.clone()),
            endpoint: None,
            endpoint_value: None,
        };
        if provide_val.as_rule() == Rule::object {
            for (k, _k_span, v) in object_fields(provide_val) {
                if k.as_ref() == "endpoint" {
                    provide.endpoint = Some(span(&v));
                    provide.endpoint_value = string_value(&v).map(Into::into);
                }
            }
        }
        out.provides.insert(provide_name, provide);
    }
}

fn extract_exports(out: &mut ManifestSpans, value: pest::iterators::Pair<'_, Rule>) {
    if value.as_rule() != Rule::object {
        return;
    }
    for (export_name, export_name_span, export_val) in object_fields(value) {
        out.exports.insert(
            export_name,
            ExportSpans {
                name: export_name_span,
                target: span(&export_val),
            },
        );
    }
}

fn extract_bindings(out: &mut ManifestSpans, value: pest::iterators::Pair<'_, Rule>) {
    if value.as_rule() != Rule::array {
        return;
    }

    for item in value.into_inner() {
        if item.as_rule() != Rule::object {
            continue;
        }

        let whole = span(&item);
        let mut fields = HashMap::<Arc<str>, (pest::iterators::Pair<'_, Rule>, SourceSpan)>::new();
        for (key, _key_span, value) in object_fields(item.clone()) {
            fields.insert(key, (value.clone(), span(&value)));
        }

        let to_value = fields
            .get("to")
            .and_then(|(p, _)| string_value(p))
            .map(Into::into);
        let from_value = fields
            .get("from")
            .and_then(|(p, _)| string_value(p))
            .map(Into::into);
        let slot_value = fields
            .get("slot")
            .and_then(|(p, _)| string_value(p))
            .map(Into::into);
        let capability_value = fields
            .get("capability")
            .and_then(|(p, _)| string_value(p))
            .map(Into::into);

        let spans = BindingSpans {
            whole,
            to: fields.get("to").map(|(_, s)| *s),
            to_value,
            from: fields.get("from").map(|(_, s)| *s),
            from_value,
            slot: fields.get("slot").map(|(_, s)| *s),
            slot_value,
            capability: fields.get("capability").map(|(_, s)| *s),
            capability_value,
            weak: fields.get("weak").map(|(_, s)| *s),
        };

        if let Some(key) = binding_target_key(&fields) {
            out.bindings.insert(key, spans.clone());
        }

        out.bindings_by_index.push(spans);
    }
}

fn binding_target_key(
    fields: &HashMap<Arc<str>, (pest::iterators::Pair<'_, Rule>, SourceSpan)>,
) -> Option<BindingTargetKey> {
    let to = fields.get("to").and_then(|(p, _)| string_value(p))?;
    let slot = fields.get("slot").and_then(|(p, _)| string_value(p));
    crate::binding_target_key_for_binding(&to, slot.as_deref())
}

fn extract_capability_decl(
    name: SourceSpan,
    value: pest::iterators::Pair<'_, Rule>,
) -> CapabilityDeclSpans {
    let whole = span(&value);
    if value.as_rule() != Rule::object {
        return CapabilityDeclSpans {
            name,
            whole,
            kind: None,
            profile: None,
        };
    }

    let mut out = CapabilityDeclSpans {
        name,
        whole,
        kind: None,
        profile: None,
    };
    for (k, _k_span, v) in object_fields(value) {
        match k.as_ref() {
            "kind" => out.kind = Some(span(&v)),
            "profile" => out.profile = Some(span(&v)),
            _ => {}
        }
    }
    out
}

fn array_string_items(array: pest::iterators::Pair<'_, Rule>) -> Vec<(Arc<str>, SourceSpan)> {
    if array.as_rule() != Rule::array {
        return Vec::new();
    }

    array
        .into_inner()
        .filter_map(|item| {
            let span = span(&item);
            let s = string_value(&item)?;
            Some((s.into(), span))
        })
        .collect()
}

fn object_fields(
    object: pest::iterators::Pair<'_, Rule>,
) -> impl Iterator<Item = (Arc<str>, SourceSpan, pest::iterators::Pair<'_, Rule>)> {
    debug_assert_eq!(object.as_rule(), Rule::object);

    let mut inner = object.into_inner();
    std::iter::from_fn(move || {
        let key_pair = inner.next()?;
        let value_pair = inner.next()?;
        let (key, key_span) = key_text(key_pair)?;
        Some((key, key_span, value_pair))
    })
}

fn key_text(pair: pest::iterators::Pair<'_, Rule>) -> Option<(Arc<str>, SourceSpan)> {
    let key_span = span(&pair);
    let out = match pair.as_rule() {
        Rule::identifier => pair.as_str().to_string(),
        Rule::string => json5::from_str::<String>(pair.as_str()).ok()?,
        _ => return None,
    };
    Some((out.into(), key_span))
}

fn string_value(pair: &pest::iterators::Pair<'_, Rule>) -> Option<String> {
    if pair.as_rule() != Rule::string {
        return None;
    }
    json5::from_str::<String>(pair.as_str()).ok()
}

fn span(pair: &pest::iterators::Pair<'_, Rule>) -> SourceSpan {
    let s = pair.as_span();
    (s.start(), s.end() - s.start()).into()
}

fn span_end(span: SourceSpan) -> usize {
    span.offset().saturating_add(span.len())
}

fn shift_span(span: SourceSpan, base: usize) -> SourceSpan {
    (base.saturating_add(span.offset()), span.len()).into()
}

fn unescape_json_pointer_segment(input: &str) -> Cow<'_, str> {
    if !input.contains('~') {
        return Cow::Borrowed(input);
    }

    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();

    while let Some(c) = chars.next() {
        if c != '~' {
            out.push(c);
            continue;
        }

        match chars.next() {
            Some('0') => out.push('~'),
            Some('1') => out.push('/'),
            Some(other) => {
                out.push('~');
                out.push(other);
            }
            None => out.push('~'),
        }
    }

    Cow::Owned(out)
}
