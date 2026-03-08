use std::fmt;

use amber_json5::{DiagnosticKind, parse};
use serde::de::{self, Visitor};
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

#[test]
fn deserialize_invalid_type_uses_concise_label() {
    #[derive(Debug)]
    struct ShellArgs;

    impl<'de> serde::Deserialize<'de> for ShellArgs {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            struct ShellArgsVisitor;

            impl<'de> Visitor<'de> for ShellArgsVisitor {
                type Value = ShellArgs;

                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("a shell-style string or an array of strings")
                }

                fn visit_str<E>(self, _value: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    Ok(ShellArgs)
                }
            }

            deserializer.deserialize_any(ShellArgsVisitor)
        }
    }

    #[derive(Debug, Deserialize)]
    struct Obj {
        #[allow(dead_code)]
        argv: ShellArgs,
    }

    let err = parse::<Obj>("{ argv: 123 }").unwrap_err();
    assert_eq!(err.kind(), DiagnosticKind::Deserialize);
    assert!(err.message().contains(
        "invalid type: integer `123`, expected a shell-style string or an array of strings"
    ));
    assert_eq!(
        err.label(),
        "expected a shell-style string or an array of strings"
    );
}
