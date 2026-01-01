use std::borrow::Cow;

use miette::SourceSpan;
use pest::Parser as _;
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "json5.pest"]
pub(crate) struct Json5Parser;

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

pub fn span_for_object_key(source: &str, object_span: SourceSpan, key: &str) -> Option<SourceSpan> {
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

pub(crate) fn object_fields(
    object: pest::iterators::Pair<'_, Rule>,
) -> impl Iterator<Item = (Cow<'_, str>, SourceSpan, pest::iterators::Pair<'_, Rule>)> {
    debug_assert_eq!(object.as_rule(), Rule::object);

    let mut inner = object.into_inner();
    std::iter::from_fn(move || {
        let key_pair = inner.next()?;
        let value_pair = inner.next()?;
        let (key, key_span) = key_text(key_pair)?;
        Some((key, key_span, value_pair))
    })
}

fn key_text(pair: pest::iterators::Pair<'_, Rule>) -> Option<(Cow<'_, str>, SourceSpan)> {
    let key_span = span(&pair);
    let out = match pair.as_rule() {
        Rule::identifier => Cow::Borrowed(pair.as_str()),
        Rule::string => Cow::Owned(json5::from_str::<String>(pair.as_str()).ok()?),
        _ => return None,
    };
    Some((out, key_span))
}

pub(crate) fn span(pair: &pest::iterators::Pair<'_, Rule>) -> SourceSpan {
    let s = pair.as_span();
    (s.start(), s.end() - s.start()).into()
}

fn span_end(span: SourceSpan) -> usize {
    span.offset().saturating_add(span.len())
}

pub(crate) fn shift_span(span: SourceSpan, base: usize) -> SourceSpan {
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
