use amber_json5::{DiagnosticKind, parse};
use serde_derive::Deserialize;

#[test]
fn parse_error_includes_span_and_label() {
    let source = "{ a \"b\" }";
    let err = parse::<serde_json::Value>(source).unwrap_err();
    assert_eq!(err.kind(), DiagnosticKind::Parse);
    assert!(err.message().starts_with("json5 parse error:"));
    assert!(err.label().contains(':'));
    assert!(err.span().len() <= 1);
}

#[test]
fn deserialize_unknown_field_points_to_key() {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[derive(Debug)]
    struct Obj {
        #[allow(dead_code)]
        a: i32,
    }

    let source = "{ a: 1, b: 2 }";
    let err = parse::<Obj>(source).unwrap_err();
    assert_eq!(err.kind(), DiagnosticKind::Deserialize);

    let key_offset = source.find('b').unwrap();
    assert_eq!(err.span(), (key_offset, 1usize).into());
}

#[test]
fn parse_error_unterminated_string_points_to_open_quote() {
    let source = "{ a: \"unterminated }";
    let err = parse::<serde_json::Value>(source).unwrap_err();
    assert_eq!(err.kind(), DiagnosticKind::Parse);
    assert!(err.label().contains("unterminated string"));

    let quote_offset = source.find('"').unwrap();
    assert_eq!(err.span(), (quote_offset, 1usize).into());
}

#[test]
fn parse_error_unclosed_array_points_to_open_bracket() {
    let source = "{ a: [1, 2";
    let err = parse::<serde_json::Value>(source).unwrap_err();
    assert_eq!(err.kind(), DiagnosticKind::Parse);
    assert!(err.label().contains("missing closing `]`"));

    let bracket_offset = source.find('[').unwrap();
    assert_eq!(err.span(), (bracket_offset, 1usize).into());
}
