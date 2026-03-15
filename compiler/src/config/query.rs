use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfigPresence {
    Present,
    Absent,
    Runtime,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ConfigEachResolution {
    Static(Vec<Value>),
    Runtime,
}

pub(crate) fn validate_config_query_syntax(query: &str) -> Result<(), String> {
    if query.is_empty() {
        return Ok(());
    }

    for seg in query.split('.') {
        if seg.is_empty() {
            return Err(format!("invalid config path {query:?}: empty segment"));
        }
    }

    Ok(())
}

pub(crate) fn parse_query_segments(query: &str) -> Result<Vec<&str>, String> {
    validate_config_query_syntax(query)?;
    if query.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(query.split('.').collect())
    }
}

pub(crate) fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_query_segments, validate_config_query_syntax};

    #[test]
    fn validate_config_query_syntax_rejects_empty_segments() {
        let err = validate_config_query_syntax("a..b").expect_err("invalid query");
        assert!(err.contains("empty segment"));
    }

    #[test]
    fn parse_query_segments_preserves_order() {
        assert_eq!(
            parse_query_segments("storage.size").unwrap(),
            vec!["storage", "size"]
        );
    }
}
