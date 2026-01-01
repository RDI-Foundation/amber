use std::fmt::{Display, Formatter};

use miette::SourceSpan;
use pest::Parser as _;
use serde::Deserialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiagnosticKind {
    Parse,
    Deserialize,
}

#[derive(Clone, Debug)]
pub struct DiagnosticError {
    kind: DiagnosticKind,
    message: String,
    label: String,
    span: SourceSpan,
    path: Option<String>,
}

impl DiagnosticError {
    #[must_use]
    pub fn kind(&self) -> DiagnosticKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    #[must_use]
    pub fn span(&self) -> SourceSpan {
        self.span
    }

    #[must_use]
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}

impl Display for DiagnosticError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DiagnosticError {}

pub fn parse<'de, T: Deserialize<'de>>(source: &'de str) -> Result<T, DiagnosticError> {
    let mut deserializer = json5::Deserializer::from_str(source);
    let res: Result<T, serde_path_to_error::Error<json5::Error>> =
        serde_path_to_error::deserialize(&mut deserializer);

    match res {
        Ok(value) => Ok(value),
        Err(err) => {
            let inner = err.inner();

            if inner.code().is_some_and(json5_error_is_parse) {
                return Err(parse_error(source, inner));
            }

            let path = err.path();
            let path_string = path.to_string();
            Err(deserialize_error(source, inner, path, &path_string))
        }
    }
}

fn parse_error(source: &str, err: &json5::Error) -> DiagnosticError {
    let hint = json5_hint(source, err);
    let label = hint
        .as_ref()
        .map_or_else(|| summarize_json5_error(err), |hint| hint.message.clone());
    let span = hint.map_or_else(|| span_for_json5_error(source, err), |hint| hint.span);
    DiagnosticError {
        kind: DiagnosticKind::Parse,
        message: format!("json5 parse error: {label}"),
        label,
        span,
        path: None,
    }
}

fn deserialize_error(
    source: &str,
    err: &json5::Error,
    path: &serde_path_to_error::Path,
    path_string: &str,
) -> DiagnosticError {
    let label = summarize_json5_path_error(source, err);
    let span = span_for_json5_deserialize_error(source, path, &label)
        .unwrap_or_else(|| span_for_json5_error(source, err));

    DiagnosticError {
        kind: DiagnosticKind::Deserialize,
        message: format!("json5 deserialize error at {path_string}: {label}"),
        label,
        span,
        path: Some(path_string.to_string()),
    }
}

fn json5_error_is_parse(code: json5::ErrorCode) -> bool {
    use json5::ErrorCode::*;

    matches!(
        code,
        EofParsingArray
            | EofParsingBool
            | EofParsingComment
            | EofParsingEscapeSequence
            | EofParsingIdentifier
            | EofParsingNull
            | EofParsingNumber
            | EofParsingObject
            | EofParsingString
            | EofParsingValue
            | ExpectedClosingBrace
            | ExpectedClosingBracket
            | ExpectedColon
            | ExpectedComma
            | ExpectedComment
            | ExpectedIdentifier
            | ExpectedValue
            | InvalidBytes
            | InvalidEscapeSequence
            | InvalidKey
            | LeadingZero
            | LineTerminatorInString
            | OverflowParsingNumber
            | TrailingCharacters
    )
}

fn span_for_json5_error(source: &str, err: &json5::Error) -> SourceSpan {
    let Some(position) = err.position() else {
        return (source.len(), 0).into();
    };
    span_for_line_col(source, position.line + 1, position.column + 1)
}

fn span_for_json5_deserialize_error(
    source: &str,
    path: &serde_path_to_error::Path,
    message: &str,
) -> Option<SourceSpan> {
    let lookup = SpanLookup::new(source, path)?;

    if message.starts_with("unknown field")
        && let Some(field) = backticked_values(message).next()
        && let Some(span) = lookup.span_for_parent_key(field)
    {
        return Some(span);
    }

    if message.contains("has `")
        && message.contains("` but is missing `")
        && let Some(field) = missing_field_present_field(message)
        && let Some(span) = lookup.span_for_present_field(field)
    {
        return Some(span);
    }

    let span = lookup.value_span()?;
    if let Some(object_span) = lookup.object_span_for_value(&span) {
        for needle in backticked_values(message) {
            if let Some(value_span) = find_string_value_in_object(source, object_span, needle) {
                return Some(value_span);
            }
        }
    }

    Some(span)
}

fn find_string_value_in_object(
    source: &str,
    object_span: SourceSpan,
    needle: &str,
) -> Option<SourceSpan> {
    let object_start = object_span.offset();
    let object_end = span_end(object_span);
    let object_src = source.get(object_start..object_end)?;

    let mut pairs = crate::spans::Json5Parser::parse(crate::spans::Rule::text, object_src).ok()?;
    let object = pairs.next()?;
    if object.as_rule() != crate::spans::Rule::object {
        return None;
    }

    for (_key, _key_span, value) in crate::spans::object_fields(object) {
        if value.as_rule() != crate::spans::Rule::string {
            continue;
        }
        let Ok(value_string) = json5::from_str::<String>(value.as_str()) else {
            continue;
        };
        if value_string == needle {
            return Some(crate::spans::shift_span(
                crate::spans::span(&value),
                object_start,
            ));
        }
    }

    None
}

#[derive(Clone, Copy, Debug)]
enum SerdePathSegment<'a> {
    Key(&'a str),
    Index(usize),
}

fn serde_path_segments(path: &serde_path_to_error::Path) -> Option<Vec<SerdePathSegment<'_>>> {
    use serde_path_to_error::Segment;

    let mut out = Vec::new();
    for segment in path.iter() {
        match segment {
            Segment::Seq { index } => out.push(SerdePathSegment::Index(*index)),
            Segment::Map { key } => out.push(SerdePathSegment::Key(key.as_str())),
            Segment::Enum { variant } => out.push(SerdePathSegment::Key(variant.as_str())),
            Segment::Unknown => return None,
        }
    }
    Some(out)
}

fn json_pointer_from_segments(segments: &[SerdePathSegment<'_>]) -> String {
    let mut out = String::new();
    for segment in segments {
        out.push('/');
        match segment {
            SerdePathSegment::Key(key) => push_json_pointer_segment(&mut out, key),
            SerdePathSegment::Index(index) => {
                use std::fmt::Write as _;
                let _ = write!(out, "{index}");
            }
        }
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

#[derive(Clone, Debug)]
struct SpanLookup<'s, 'p> {
    source: &'s str,
    root: SourceSpan,
    segments: Vec<SerdePathSegment<'p>>,
    pointer: String,
}

impl<'s, 'p> SpanLookup<'s, 'p> {
    fn new(source: &'s str, path: &'p serde_path_to_error::Path) -> Option<Self> {
        let segments = serde_path_segments(path)?;
        let pointer = json_pointer_from_segments(&segments);
        Some(Self {
            source,
            root: (0usize, source.len()).into(),
            segments,
            pointer,
        })
    }

    fn span_for_pointer(&self, pointer: &str) -> Option<SourceSpan> {
        crate::spans::span_for_json_pointer(self.source, self.root, pointer)
    }

    fn value_span(&self) -> Option<SourceSpan> {
        self.span_for_pointer(&self.pointer)
    }

    fn span_for_parent_key(&self, field: &str) -> Option<SourceSpan> {
        let mut parent = self.segments.clone();
        if parent
            .last()
            .is_some_and(|s| matches!(s, SerdePathSegment::Key(key) if *key == field))
        {
            parent.pop();
        }
        let parent_pointer = json_pointer_from_segments(&parent);
        let parent_span = self.span_for_pointer(&parent_pointer)?;
        crate::spans::span_for_object_key(self.source, parent_span, field)
    }

    fn span_for_present_field(&self, field: &str) -> Option<SourceSpan> {
        let mut pointer = self.pointer.clone();
        pointer.push('/');
        push_json_pointer_segment(&mut pointer, field);
        self.span_for_pointer(&pointer)
    }

    fn object_span_for_value(&self, value_span: &SourceSpan) -> Option<SourceSpan> {
        if self.segments.is_empty() {
            return None;
        }

        let mut parent = self.segments.clone();
        if matches!(parent.last(), Some(SerdePathSegment::Key(_))) {
            parent.pop();
        }
        let parent_pointer = json_pointer_from_segments(&parent);
        let parent_span = self.span_for_pointer(&parent_pointer)?;

        if parent_span.offset() <= value_span.offset()
            && span_end(parent_span) >= span_end(*value_span)
        {
            return Some(parent_span);
        }

        None
    }
}

fn backticked_values(message: &str) -> impl Iterator<Item = &str> {
    message.split('`').skip(1).step_by(2)
}

fn missing_field_present_field(message: &str) -> Option<&str> {
    // Match: "has `slot` but is missing `capability` ..."
    let mut it = backticked_values(message);
    let first = it.next()?;
    let _second = it.next()?;
    Some(first)
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
    String,
    Identifier,
    Number,
    Literal,
}

fn needs_unterminated_string_hint(code: json5::ErrorCode) -> bool {
    matches!(
        code,
        json5::ErrorCode::EofParsingString | json5::ErrorCode::LineTerminatorInString
    )
}

fn needs_container_hint(code: json5::ErrorCode) -> bool {
    matches!(
        code,
        json5::ErrorCode::EofParsingArray
            | json5::ErrorCode::EofParsingObject
            | json5::ErrorCode::EofParsingValue
            | json5::ErrorCode::ExpectedClosingBrace
            | json5::ErrorCode::ExpectedClosingBracket
    )
}

fn json5_hint(source: &str, err: &json5::Error) -> Option<Json5Hint> {
    let code = err.code()?;

    let wants_unterminated = needs_unterminated_string_hint(code);
    let wants_container = needs_container_hint(code);

    if wants_unterminated || wants_container {
        match tokenize_json5(source) {
            Err(TokenizeError::UnterminatedString { start }) if wants_unterminated => {
                return Some(Json5Hint {
                    message: "unterminated string (missing closing quote)".to_string(),
                    span: (start, 1).into(),
                });
            }
            Ok(tokens) if wants_container => {
                if let Some(hint) = unclosed_container_hint(&tokens) {
                    return Some(hint);
                }
            }
            _ => {}
        }
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
                    match bytes[i] {
                        b'\\' => {
                            i += 2;
                        }
                        c if c == quote => {
                            i += 1;
                            tokens.push(Token {
                                kind: TokenKind::String,
                                span: (start, i - start).into(),
                            });
                            break;
                        }
                        b'\n' | b'\r' => break,
                        _ => i += 1,
                    }
                }
                if i >= bytes.len() || bytes[i.saturating_sub(1)] != quote {
                    return Err(TokenizeError::UnterminatedString { start });
                }
            }
            b'0'..=b'9' | b'.' | b'+' | b'-' => {
                let start = i;
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'0'..=b'9'
                        | b'.'
                        | b'e'
                        | b'E'
                        | b'+'
                        | b'-'
                        | b'x'
                        | b'X'
                        | b'a'..=b'f'
                        | b'A'..=b'F' => i += 1,
                        _ => break,
                    }
                }
                tokens.push(Token {
                    kind: TokenKind::Number,
                    span: (start, i - start).into(),
                });
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$' => {
                let start = i;
                i += 1;
                while i < bytes.len() {
                    match bytes[i] {
                        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$' => i += 1,
                        _ => break,
                    }
                }
                tokens.push(Token {
                    kind: TokenKind::Identifier,
                    span: (start, i - start).into(),
                });
            }
            _ => {
                let start = i;
                i += 1;
                tokens.push(Token {
                    kind: TokenKind::Literal,
                    span: (start, 1).into(),
                });
            }
        }
    }
    Ok(tokens)
}

fn unclosed_container_hint(tokens: &[Token]) -> Option<Json5Hint> {
    let mut stack = Vec::<&Token>::new();

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
        TokenKind::String => Some("string"),
        TokenKind::Number => Some("number"),
        TokenKind::Literal => json5_literal_kind(source, token.span),
        TokenKind::Identifier => json5_identifier_kind(source, token.span),
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

fn json5_identifier_kind(source: &str, span: SourceSpan) -> Option<&'static str> {
    let raw = source.get(span.offset()..span_end(span))?;
    let raw = raw.trim();
    Some(match raw {
        "true" | "false" => "boolean",
        "null" => "null",
        "Infinity" | "NaN" => "number",
        _ => "identifier",
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
