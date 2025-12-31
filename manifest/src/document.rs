#![allow(clippy::result_large_err)]

use std::sync::Arc;

use miette::{Diagnostic, LabeledSpan, NamedSource, SourceCode, SourceSpan};
use thiserror::Error;

use crate::{Error as ManifestError, Manifest, ManifestSpans, RawManifest};

#[derive(Clone, Debug)]
pub struct ParsedManifest {
    pub manifest: Manifest,
    pub source: Arc<str>,
    pub spans: Arc<ManifestSpans>,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct ManifestDocError {
    pub kind: ManifestError,
    message: String,
    src: NamedSource<Arc<str>>,
    labels: Vec<LabeledSpan>,
    help: Option<String>,
}

impl ManifestDocError {
    pub fn new(
        name: impl AsRef<str>,
        source: Arc<str>,
        spans: &ManifestSpans,
        kind: ManifestError,
    ) -> Self {
        let src = NamedSource::new(name, Arc::clone(&source)).with_language("json5");
        let hint = match &kind {
            ManifestError::Json5(parse) => json5_hint(&source, parse),
            _ => None,
        };
        let message = message_for_manifest_error(&kind, hint.as_ref(), &source);
        let labels = labels_for_manifest_error(&kind, &source, spans, hint.as_ref());
        let help = help_for_manifest_error(&kind);
        Self {
            kind,
            message,
            src,
            labels,
            help,
        }
    }
}

impl Diagnostic for ManifestDocError {
    fn code<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.kind.code()
    }

    fn severity(&self) -> Option<miette::Severity> {
        self.kind.severity()
    }

    fn help<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.help.as_ref().map_or_else(
            || self.kind.help(),
            |help| Some(Box::new(help.as_str()) as Box<dyn std::fmt::Display + 'a>),
        )
    }

    fn url<'a>(&'a self) -> Option<Box<dyn std::fmt::Display + 'a>> {
        self.kind.url()
    }

    fn source_code(&self) -> Option<&dyn SourceCode> {
        Some(&self.src)
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = LabeledSpan> + '_>> {
        (!self.labels.is_empty()).then(|| Box::new(self.labels.iter().cloned()) as _)
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.kind.diagnostic_source()
    }
}

impl ParsedManifest {
    pub fn parse_named(name: impl AsRef<str>, source: Arc<str>) -> Result<Self, ManifestDocError> {
        let spans = Arc::new(ManifestSpans::parse(&source));

        let mut deserializer = json5::Deserializer::from_str(&source);
        let raw: RawManifest =
            serde_path_to_error::deserialize(&mut deserializer).map_err(|e| {
                let kind = match e.inner().code() {
                    Some(code) if crate::json5_error_is_parse(code) => {
                        ManifestError::Json5(e.into_inner())
                    }
                    _ => ManifestError::Json5Path(e),
                };
                ManifestDocError::new(name.as_ref(), Arc::clone(&source), &spans, kind)
            })?;

        let manifest = raw
            .validate()
            .map_err(|e| ManifestDocError::new(name.as_ref(), Arc::clone(&source), &spans, e))?;

        Ok(Self {
            manifest,
            source,
            spans,
        })
    }
}

fn labels_for_manifest_error(
    err: &ManifestError,
    source: &str,
    spans: &ManifestSpans,
    hint: Option<&Json5Hint>,
) -> Vec<LabeledSpan> {
    match err {
        ManifestError::Json5(parse) => {
            let (span, label) = hint.map_or_else(
                || {
                    (
                        span_for_json5_error(source, parse),
                        summarize_json5_error(parse),
                    )
                },
                |hint| (hint.span, hint.message.clone()),
            );
            vec![LabeledSpan::new_primary_with_span(Some(label), span)]
        }
        ManifestError::Json5Path(de) => {
            let label = summarize_json5_path_error(source, de.inner());
            let span = span_for_json5_path_error(de.path(), source, spans, &label)
                .unwrap_or_else(|| span_for_json5_error(source, de.inner()));
            vec![primary(span, Some(label))]
        }
        ManifestError::UnsupportedManifestVersion { .. } => vec![primary(
            spans.manifest_version.unwrap_or((0usize, 0usize).into()),
            Some("unsupported `manifest_version`".to_string()),
        )],
        ManifestError::InvalidName { kind, name } => {
            let span = match *kind {
                "environment" => spans.environments.get(name.as_str()).map(|s| s.name),
                "child" => spans.components.get(name.as_str()).map(|s| s.name),
                "slot" => spans.slots.get(name.as_str()).map(|s| s.name),
                "provide" => spans.provides.get(name.as_str()).map(|s| s.capability.name),
                "export" => spans.exports.get(name.as_str()).map(|s| s.name),
                _ => None,
            };
            vec![primary(
                span.unwrap_or((0usize, 0usize).into()),
                Some("invalid name".to_string()),
            )]
        }
        ManifestError::UnknownExportTarget { export, .. }
        | ManifestError::UnknownExportChild { export, .. } => {
            let span = spans
                .exports
                .get(export.as_str())
                .map(|s| s.target)
                .unwrap_or((0usize, 0usize).into());
            vec![primary(span, Some("export target here".to_string()))]
        }
        ManifestError::AmbiguousCapabilityName { name } => {
            let mut labels = Vec::new();
            if let Some(slot) = spans.slots.get(name.as_str()) {
                labels.push(primary(
                    slot.name,
                    Some("declared as a slot here".to_string()),
                ));
            }
            if let Some(provide) = spans.provides.get(name.as_str()) {
                labels.push(LabeledSpan::new_with_span(
                    Some("declared as a provide here".to_string()),
                    provide.capability.name,
                ));
            }
            labels
        }
        ManifestError::DuplicateBindingTarget { to, slot } => {
            let Some(key) = crate::binding_target_key_for_binding(to, Some(slot.as_str())) else {
                return vec![primary(
                    (0usize, 0usize).into(),
                    Some("duplicate binding target".to_string()),
                )];
            };

            let matches: Vec<_> = spans
                .bindings_by_index
                .iter()
                .filter(|b| {
                    binding_target_key_for_span(b)
                        .as_ref()
                        .is_some_and(|k| k == &key)
                })
                .map(|b| b.whole)
                .collect();

            if matches.is_empty() {
                return vec![primary(
                    (0usize, 0usize).into(),
                    Some("duplicate binding target".to_string()),
                )];
            }

            if matches.len() == 1 {
                return vec![primary(
                    matches[0],
                    Some("duplicate binding target".to_string()),
                )];
            }

            let mut labels = Vec::new();
            labels.push(primary(matches[1], Some("second binding here".to_string())));
            labels.push(LabeledSpan::new_with_span(
                Some("first binding here".to_string()),
                matches[0],
            ));
            for &s in &matches[2..] {
                labels.push(LabeledSpan::new_with_span(None, s));
            }
            labels
        }
        ManifestError::UnknownBindingSlot { slot } => {
            let key = crate::BindingTargetKey::SelfSlot(slot.as_str().into());
            let binding = spans.bindings.get(&key);
            let span = binding
                .and_then(|b| b.slot.or(b.to).or(Some(b.whole)))
                .unwrap_or((0usize, 0usize).into());
            vec![primary(
                span,
                Some("unknown slot referenced here".to_string()),
            )]
        }
        ManifestError::UnknownBindingProvide { capability } => {
            let needle = capability.as_str();
            let label = Some("unknown provide referenced here".to_string());
            let span = spans
                .bindings
                .values()
                .find_map(|b| {
                    if b.capability_value.as_deref() == Some(needle) {
                        return b.capability.or(b.from).or(Some(b.whole));
                    }
                    if b.from_value
                        .as_deref()
                        .and_then(|from| from.strip_prefix("self."))
                        .is_some_and(|name| name == needle)
                    {
                        return b.from.or(Some(b.whole));
                    }
                    None
                })
                .unwrap_or((0usize, 0usize).into());
            vec![primary(span, label)]
        }
        ManifestError::UnknownBindingChild { child } => {
            let needle = format!("#{child}");
            let needle_dot = format!("{needle}.");
            let span = spans
                .bindings
                .values()
                .find_map(|b| {
                    if b.to_value.as_deref() == Some(needle.as_str())
                        || b.to_value
                            .as_deref()
                            .is_some_and(|to| to.starts_with(&needle_dot))
                    {
                        return b.to.or(Some(b.whole));
                    }
                    if b.from_value.as_deref() == Some(needle.as_str())
                        || b.from_value
                            .as_deref()
                            .is_some_and(|from| from.starts_with(&needle_dot))
                    {
                        return b.from.or(Some(b.whole));
                    }
                    None
                })
                .unwrap_or((0usize, 0usize).into());
            vec![primary(
                span,
                Some("unknown child referenced here".to_string()),
            )]
        }
        ManifestError::DuplicateEndpointName { name } => {
            let Some(program) = &spans.program else {
                return Vec::new();
            };

            let matches: Vec<_> = program
                .endpoints
                .iter()
                .filter_map(|(n, s)| (n.as_ref() == name).then_some(*s))
                .collect();

            if matches.is_empty() {
                return Vec::new();
            }

            let mut labels = Vec::new();
            let (primary_span, rest) = matches
                .get(1)
                .copied()
                .map(|s| (s, &matches[..]))
                .unwrap_or((matches[0], &matches[..]));
            labels.push(primary(
                primary_span,
                Some("duplicate endpoint name".to_string()),
            ));
            for &s in rest {
                if s == primary_span {
                    continue;
                }
                labels.push(LabeledSpan::new_with_span(None, s));
            }
            labels
        }
        ManifestError::UnknownEndpoint { name } => {
            let span = spans
                .provides
                .values()
                .find_map(|p| {
                    (p.endpoint_value.as_deref() == Some(name.as_str()))
                        .then_some(p.endpoint)
                        .flatten()
                })
                .unwrap_or_else(|| {
                    spans
                        .program
                        .as_ref()
                        .map(|p| p.whole)
                        .unwrap_or((0usize, 0usize).into())
                });
            vec![primary(
                span,
                Some("unknown endpoint referenced here".to_string()),
            )]
        }
        ManifestError::InvalidConfigSchema(_) => vec![primary(
            spans.config_schema.unwrap_or((0usize, 0usize).into()),
            Some("invalid schema here".to_string()),
        )],
        ManifestError::UnknownEnvironmentExtends { name, .. } => {
            let env = spans.environments.get(name.as_str());
            let span = env
                .and_then(|e| e.extends)
                .unwrap_or((0usize, 0usize).into());
            vec![primary(span, Some("unknown environment here".to_string()))]
        }
        ManifestError::EnvironmentCycle { name } => {
            let env = spans.environments.get(name.as_str());
            let span = env.map(|e| e.name).unwrap_or((0usize, 0usize).into());
            vec![primary(span, Some("cycle originates here".to_string()))]
        }
        ManifestError::UnknownComponentEnvironment { child, .. } => {
            let span = spans
                .components
                .get(child.as_str())
                .and_then(|c| c.environment.or(Some(c.name)))
                .unwrap_or((0usize, 0usize).into());
            vec![primary(
                span,
                Some("unknown environment referenced here".to_string()),
            )]
        }
        _ => Vec::new(),
    }
}

fn help_for_manifest_error(err: &ManifestError) -> Option<String> {
    match err {
        ManifestError::Json5Path(de) => {
            let message = de.inner().to_string();
            (message.starts_with("missing field `manifest_version`"))
                .then(|| "add `manifest_version: \"0.1.0\"` to the root object".to_string())
        }
        _ => None,
    }
}

fn primary(span: SourceSpan, label: Option<String>) -> LabeledSpan {
    LabeledSpan::new_primary_with_span(label, span)
}

fn binding_target_key_for_span(span: &crate::BindingSpans) -> Option<crate::BindingTargetKey> {
    let to = span.to_value.as_deref()?;
    crate::binding_target_key_for_binding(to, span.slot_value.as_deref())
}

fn span_for_json5_error(source: &str, err: &json5::Error) -> SourceSpan {
    let Some(position) = err.position() else {
        return (source.len(), 0).into();
    };
    span_for_line_col(source, position.line + 1, position.column + 1)
}

fn span_for_json5_path_error(
    path: &serde_path_to_error::Path,
    source: &str,
    spans: &ManifestSpans,
    message: &str,
) -> Option<SourceSpan> {
    let path = path.to_string();
    if let Some((idx, rest)) = binding_index_from_path(&path) {
        let binding = spans.bindings_by_index.get(idx)?;
        return Some(span_for_binding_path(source, binding, rest, message));
    }

    span_for_non_binding_path_error(source, &path, message)
}

fn binding_index_from_path(path: &str) -> Option<(usize, &str)> {
    let rest = path.strip_prefix("bindings[")?;
    let (idx, rest) = rest.split_once(']')?;
    let idx = idx.parse::<usize>().ok()?;
    let rest = rest.strip_prefix('.').unwrap_or(rest);
    Some((idx, rest))
}

fn span_for_binding_path(
    source: &str,
    binding: &crate::BindingSpans,
    rest: &str,
    message: &str,
) -> SourceSpan {
    if message.starts_with("missing field")
        || message.contains("missing required field")
        || message.contains("did not match any variant")
    {
        return binding.whole;
    }

    if message.starts_with("unknown field") {
        if !rest.is_empty()
            && let Some(span) = find_object_key_span(source, binding.whole, rest)
        {
            return span;
        }
        return binding.whole;
    }

    match rest {
        "to" => binding.to.unwrap_or(binding.whole),
        "from" => binding.from.unwrap_or(binding.whole),
        "slot" => binding.slot.unwrap_or(binding.whole),
        "capability" => binding.capability.unwrap_or(binding.whole),
        "weak" => binding.weak.unwrap_or(binding.whole),
        "" => span_for_binding_root_error(binding, message),
        _ => binding.whole,
    }
}

fn span_for_binding_root_error(binding: &crate::BindingSpans, message: &str) -> SourceSpan {
    if message.contains("has `slot` but is missing `capability`") {
        return binding.slot.unwrap_or(binding.whole);
    }
    if message.contains("has `capability` but is missing `slot`") {
        return binding.capability.unwrap_or(binding.whole);
    }

    for value in backticked_values(message) {
        if binding.to_value.as_deref() == Some(value) {
            return binding.to.unwrap_or(binding.whole);
        }
        if binding.from_value.as_deref() == Some(value) {
            return binding.from.unwrap_or(binding.whole);
        }
        if binding.slot_value.as_deref() == Some(value) {
            return binding.slot.unwrap_or(binding.whole);
        }
        if binding.capability_value.as_deref() == Some(value) {
            return binding.capability.unwrap_or(binding.whole);
        }
    }

    binding.whole
}

fn span_for_non_binding_path_error(source: &str, path: &str, message: &str) -> Option<SourceSpan> {
    let root: SourceSpan = (0usize, source.len()).into();
    let segments = serde_path_segments(path)?;
    let pointer = json_pointer_from_segments(&segments);

    if message.starts_with("unknown field")
        && let Some(field) = backticked_values(message).next()
    {
        let mut parent = segments.clone();
        if parent.last().is_some_and(|s| s == field) {
            parent.pop();
        }
        let parent_pointer = json_pointer_from_segments(&parent);
        if let Some(parent_span) = crate::span_for_json_pointer(source, root, &parent_pointer)
            && let Some(span) = find_object_key_span(source, parent_span, field)
        {
            return Some(span);
        }
    }

    crate::span_for_json_pointer(source, root, &pointer)
}

fn serde_path_segments(path: &str) -> Option<Vec<String>> {
    if path.is_empty() {
        return Some(Vec::new());
    }

    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < path.len() {
        match path.as_bytes()[idx] {
            b'.' => {
                idx += 1;
            }
            b'[' => {
                let rest = path.get(idx + 1..)?;
                let end = rest.find(']')?;
                let inner = rest.get(..end)?;
                if inner.starts_with('"') || inner.starts_with('\'') {
                    let key: String = json5::from_str(inner).ok()?;
                    out.push(key);
                } else {
                    out.push(inner.to_string());
                }
                idx += end + 2;
            }
            _ => {
                let start = idx;
                idx += 1;
                while idx < path.len() && !matches!(path.as_bytes()[idx], b'.' | b'[') {
                    idx += 1;
                }
                out.push(path.get(start..idx)?.to_string());
            }
        }
    }

    Some(out)
}

fn json_pointer_from_segments(segments: &[String]) -> String {
    if segments.is_empty() {
        return String::new();
    }

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

fn backticked_values(message: &str) -> impl Iterator<Item = &str> {
    message.split('`').skip(1).step_by(2)
}

fn message_for_manifest_error(
    err: &ManifestError,
    hint: Option<&Json5Hint>,
    source: &str,
) -> String {
    match err {
        ManifestError::Json5(parse) => format!(
            "json5 parse error: {}",
            hint.map_or_else(|| summarize_json5_error(parse), |hint| hint.message.clone())
        ),
        ManifestError::Json5Path(de) => format!(
            "json5 deserialize error at {}: {}",
            de.path(),
            summarize_json5_path_error(source, de.inner())
        ),
        other => other.to_string(),
    }
}

#[derive(Clone, Debug)]
struct Json5Hint {
    message: String,
    span: SourceSpan,
}

#[derive(Debug)]
enum TokenizeError {
    UnterminatedString { start: usize },
}

#[derive(Clone, Debug)]
struct Token {
    kind: TokenKind,
    span: SourceSpan,
}

#[derive(Clone, Debug)]
enum TokenKind {
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Colon,
    Comma,
    String(String),
    Identifier(String),
    Number,
    Literal,
}

impl TokenKind {
    fn key_name(&self) -> Option<&str> {
        match self {
            TokenKind::String(value) | TokenKind::Identifier(value) => Some(value.as_str()),
            _ => None,
        }
    }
}

fn json5_hint(source: &str, err: &json5::Error) -> Option<Json5Hint> {
    let code = err.code()?;

    if matches!(
        code,
        json5::ErrorCode::EofParsingString | json5::ErrorCode::LineTerminatorInString
    ) && let Err(TokenizeError::UnterminatedString { start }) = tokenize_json5(source)
    {
        return Some(Json5Hint {
            message: "unterminated string (missing closing quote)".to_string(),
            span: (start, 1).into(),
        });
    }

    if matches!(
        code,
        json5::ErrorCode::EofParsingArray
            | json5::ErrorCode::EofParsingObject
            | json5::ErrorCode::EofParsingValue
            | json5::ErrorCode::ExpectedClosingBrace
            | json5::ErrorCode::ExpectedClosingBracket
    ) && let Ok(tokens) = tokenize_json5(source)
        && let Some(hint) = unclosed_container_hint(&tokens)
    {
        return Some(hint);
    }

    Some(Json5Hint {
        message: summarize_json5_error(err),
        span: span_for_json5_error(source, err),
    })
}

fn tokenize_json5(source: &str) -> Result<Vec<Token>, TokenizeError> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\n' | b'\r' | b'\t' => {
                i += 1;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                if i + 1 < bytes.len() {
                    i += 2;
                }
            }
            b'{' => {
                tokens.push(Token {
                    kind: TokenKind::LBrace,
                    span: (i, 1).into(),
                });
                i += 1;
            }
            b'}' => {
                tokens.push(Token {
                    kind: TokenKind::RBrace,
                    span: (i, 1).into(),
                });
                i += 1;
            }
            b'[' => {
                tokens.push(Token {
                    kind: TokenKind::LBracket,
                    span: (i, 1).into(),
                });
                i += 1;
            }
            b']' => {
                tokens.push(Token {
                    kind: TokenKind::RBracket,
                    span: (i, 1).into(),
                });
                i += 1;
            }
            b':' => {
                tokens.push(Token {
                    kind: TokenKind::Colon,
                    span: (i, 1).into(),
                });
                i += 1;
            }
            b',' => {
                tokens.push(Token {
                    kind: TokenKind::Comma,
                    span: (i, 1).into(),
                });
                i += 1;
            }
            b'"' | b'\'' => {
                let quote = bytes[i];
                let start = i;
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' {
                        i += 1;
                        if i < bytes.len() {
                            i += 1;
                        }
                        continue;
                    }
                    if bytes[i] == b'\n' || bytes[i] == b'\r' {
                        return Err(TokenizeError::UnterminatedString { start });
                    }
                    if bytes[i] == quote {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                if i > bytes.len() || bytes[i - 1] != quote {
                    return Err(TokenizeError::UnterminatedString { start });
                }
                let raw = &source[start..i];
                let parsed = json5::from_str::<String>(raw)
                    .ok()
                    .unwrap_or_else(|| raw[1..raw.len() - 1].to_string());
                tokens.push(Token {
                    kind: TokenKind::String(parsed),
                    span: (start, i - start).into(),
                });
            }
            b'-' | b'0'..=b'9' => {
                let start = i;
                i += 1;
                while i < bytes.len()
                    && matches!(bytes[i], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                {
                    i += 1;
                }
                tokens.push(Token {
                    kind: TokenKind::Number,
                    span: (start, i - start).into(),
                });
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$' => {
                let start = i;
                i += 1;
                while i < bytes.len()
                    && matches!(bytes[i], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$')
                {
                    i += 1;
                }
                let ident = &source[start..i];
                let kind = match ident {
                    "true" | "false" | "null" | "Infinity" | "NaN" => TokenKind::Literal,
                    _ => TokenKind::Identifier(ident.to_string()),
                };
                tokens.push(Token {
                    kind,
                    span: (start, i - start).into(),
                });
            }
            _ => {
                i += 1;
            }
        }
    }
    Ok(tokens)
}

fn unclosed_container_hint(tokens: &[Token]) -> Option<Json5Hint> {
    let mut stack: Vec<&Token> = Vec::new();
    for token in tokens {
        match &token.kind {
            TokenKind::LBrace | TokenKind::LBracket => stack.push(token),
            TokenKind::RBrace => {
                if stack
                    .last()
                    .is_some_and(|open| matches!(&open.kind, TokenKind::LBrace))
                {
                    stack.pop();
                }
            }
            TokenKind::RBracket => {
                if stack
                    .last()
                    .is_some_and(|open| matches!(&open.kind, TokenKind::LBracket))
                {
                    stack.pop();
                }
            }
            _ => {}
        }
    }

    let open = stack.last()?;
    let message = match &open.kind {
        TokenKind::LBrace => "missing closing `}` for object opened here",
        TokenKind::LBracket => "missing closing `]` for array opened here",
        _ => return None,
    };
    Some(Json5Hint {
        message: message.to_string(),
        span: open.span,
    })
}

fn summarize_json5_error(err: &json5::Error) -> String {
    let Some(code) = err.code() else {
        let mut message = err.to_string();
        if let Some(idx) = message.find(" at line ") {
            message.truncate(idx);
        }
        return message;
    };

    json5_error_code_summary(code).to_string()
}

fn summarize_json5_path_error(source: &str, err: &json5::Error) -> String {
    let Some(code) = err.code() else {
        return summarize_json5_error(err);
    };

    let Some(expected) = json5_expected_value_label(code) else {
        return summarize_json5_error(err);
    };

    let found = json5_found_value_type(source, err);
    match found {
        Some(found) => format!("expected {expected}, found {found}"),
        None => format!("expected {expected}"),
    }
}

fn json5_expected_value_label(code: json5::ErrorCode) -> Option<&'static str> {
    use json5::ErrorCode::*;

    match code {
        ExpectedOpeningBrace => Some("object"),
        ExpectedOpeningBracket => Some("array"),
        ExpectedBool => Some("boolean"),
        ExpectedString => Some("string"),
        ExpectedNumber => Some("number"),
        ExpectedNull => Some("null"),
        _ => None,
    }
}

fn json5_found_value_type(source: &str, err: &json5::Error) -> Option<&'static str> {
    let position = err.position()?;
    let span = span_for_line_col(source, position.line + 1, position.column + 1);
    let offset = span.offset();
    let tokens = tokenize_json5(source).ok()?;
    let token = token_at_offset(&tokens, offset)?;
    json5_token_value_kind(source, token)
}

fn token_at_offset(tokens: &[Token], offset: usize) -> Option<&Token> {
    let mut next = None;
    for token in tokens {
        let start = token.span.offset();
        let end = span_end(token.span);
        if offset >= start && offset < end {
            return Some(token);
        }
        if start >= offset && next.is_none() {
            next = Some(token);
        }
    }
    next
}

fn json5_token_value_kind(source: &str, token: &Token) -> Option<&'static str> {
    match &token.kind {
        TokenKind::LBrace => Some("object"),
        TokenKind::LBracket => Some("array"),
        TokenKind::String(_) => Some("string"),
        TokenKind::Number => Some("number"),
        TokenKind::Literal => json5_literal_kind(source, token.span),
        TokenKind::Identifier(_) => Some("identifier"),
        _ => None,
    }
}

fn json5_literal_kind(source: &str, span: SourceSpan) -> Option<&'static str> {
    let raw = source.get(span.offset()..span_end(span))?;
    let raw = raw.trim();
    Some(match raw {
        "true" | "false" => "boolean",
        "null" => "null",
        "Infinity" | "NaN" => "number",
        _ => "literal",
    })
}

fn json5_error_code_summary(code: json5::ErrorCode) -> &'static str {
    use json5::ErrorCode::*;

    match code {
        EofParsingArray => "unexpected EOF while parsing array",
        EofParsingBool => "unexpected EOF while parsing bool",
        EofParsingComment => "unexpected EOF while parsing comment",
        EofParsingEscapeSequence => "unexpected EOF while parsing escape sequence",
        EofParsingIdentifier => "unexpected EOF while parsing identifier",
        EofParsingNull => "unexpected EOF while parsing null",
        EofParsingNumber => "unexpected EOF while parsing number",
        EofParsingObject => "unexpected EOF while parsing object",
        EofParsingString => "unterminated string (missing closing quote)",
        EofParsingValue => "unexpected EOF while parsing value",

        ExpectedBool => "expected `true` or `false`",
        ExpectedClosingBrace => "missing closing `}`",
        ExpectedClosingBracket => "missing closing `]`",
        ExpectedColon => "missing `:`",
        ExpectedComma => "missing `,`",
        ExpectedComment => "expected comment",
        ExpectedIdentifier => "expected identifier",
        ExpectedNull => "expected `null`",
        ExpectedNumber => "expected number",
        ExpectedOpeningBrace => "expected `{`",
        ExpectedOpeningBracket => "expected `[`",
        ExpectedString => "expected string",
        ExpectedStringOrObject => "expected string or object",
        ExpectedValue => "expected value",

        InvalidBytes => "invalid bytes",
        InvalidEscapeSequence => "invalid escape sequence",
        InvalidKey => "invalid object key",
        LeadingZero => "leading zero is not allowed",
        LineTerminatorInString => "unterminated string (missing closing quote)",
        OverflowParsingNumber => "number is too large",
        TrailingCharacters => "trailing characters after JSON5 value",
    }
}

fn span_for_line_col(source: &str, line: usize, column: usize) -> SourceSpan {
    if line == 0 || column == 0 {
        return (0usize, 0usize).into();
    }

    let mut current_line = 1usize;
    let mut line_start = 0usize;
    for (idx, c) in source.char_indices() {
        if current_line == line {
            break;
        }
        if c == '\n' {
            current_line += 1;
            line_start = idx + c.len_utf8();
        }
    }
    if current_line != line {
        return (source.len(), 0).into();
    }

    let line_slice = source.get(line_start..).unwrap_or_default();
    let line_end_rel = line_slice.find('\n').unwrap_or(line_slice.len());
    let line_end = line_start + line_end_rel;

    let mut col = 1usize;
    let mut byte_offset = line_start;
    for (rel, c) in line_slice[..line_end_rel].char_indices() {
        if col == column {
            byte_offset = line_start + rel;
            break;
        }
        col += 1;
        byte_offset = line_start + rel + c.len_utf8();
    }
    if column > col {
        byte_offset = line_end;
    }

    let len = source
        .get(byte_offset..line_end)
        .and_then(|s| s.chars().next().map(|c| c.len_utf8()))
        .unwrap_or(0);

    (byte_offset, len).into()
}

fn span_end(span: SourceSpan) -> usize {
    span.offset().saturating_add(span.len())
}

fn span_in_range(span: SourceSpan, start: usize, end: usize) -> bool {
    let span_start = span.offset();
    let span_end = span_end(span);
    span_start >= start && span_end <= end
}

fn find_object_key_span(source: &str, range: SourceSpan, key: &str) -> Option<SourceSpan> {
    let tokens = tokenize_json5(source).ok()?;
    let start = range.offset();
    let end = span_end(range);
    let mut depth = 0usize;

    for (idx, token) in tokens.iter().enumerate() {
        if !span_in_range(token.span, start, end) {
            continue;
        }

        match token.kind {
            TokenKind::LBrace | TokenKind::LBracket => {
                depth += 1;
                continue;
            }
            TokenKind::RBrace | TokenKind::RBracket => {
                depth = depth.saturating_sub(1);
                continue;
            }
            _ => {}
        }

        if depth != 1 {
            continue;
        }

        let Some(name) = token.kind.key_name() else {
            continue;
        };
        if name != key {
            continue;
        }

        if let Some(next) = tokens.get(idx + 1)
            && matches!(next.kind, TokenKind::Colon)
            && span_in_range(next.span, start, end)
        {
            return Some(token.span);
        }
    }

    None
}
