use std::{collections::BTreeMap, fmt};

#[derive(Clone, Debug)]
pub(crate) struct BindingObject {
    pub(crate) url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BindingQuery<'a> {
    pub(crate) name: &'a str,
}

#[derive(Debug)]
pub(crate) enum BindingQueryError {
    MissingBindingName,
    MissingField,
    EmptySegment { query: String },
    UnsupportedField { field: String },
    UnsupportedPath { path: String },
}

impl fmt::Display for BindingQueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindingQueryError::MissingBindingName => {
                f.write_str("missing binding name (expected bindings.<name>.url)")
            }
            BindingQueryError::MissingField => {
                f.write_str("missing binding field (expected bindings.<name>.url)")
            }
            BindingQueryError::EmptySegment { query } => {
                write!(f, "invalid bindings path {query:?}: empty segment")
            }
            BindingQueryError::UnsupportedField { field } => write!(
                f,
                "unsupported bindings field {field:?} (only \"url\" is supported)"
            ),
            BindingQueryError::UnsupportedPath { path } => write!(
                f,
                "unsupported bindings path {path:?} (only \"url\" is supported)"
            ),
        }
    }
}

pub(crate) fn parse_binding_query(query: &str) -> Result<BindingQuery<'_>, BindingQueryError> {
    if query.is_empty() {
        return Err(BindingQueryError::MissingBindingName);
    }

    let mut segments = query.split('.');
    let name = segments.next().unwrap_or_default();
    if name.is_empty() {
        return Err(BindingQueryError::MissingBindingName);
    }

    let rest: Vec<&str> = segments.collect();
    if rest.iter().any(|seg| seg.is_empty()) {
        return Err(BindingQueryError::EmptySegment {
            query: query.to_string(),
        });
    }

    match rest.as_slice() {
        [] => Err(BindingQueryError::MissingField),
        ["url"] => Ok(BindingQuery { name }),
        [other] => Err(BindingQueryError::UnsupportedField {
            field: (*other).to_string(),
        }),
        _ => Err(BindingQueryError::UnsupportedPath {
            path: rest.join("."),
        }),
    }
}

pub(crate) fn resolve_binding_query(
    bindings: &BTreeMap<String, BindingObject>,
    query: &str,
) -> Result<String, String> {
    let label = if query.is_empty() {
        "bindings".to_string()
    } else {
        format!("bindings.{query}")
    };

    let parsed = parse_binding_query(query)
        .map_err(|err| format!("invalid bindings interpolation '{label}': {err}"))?;

    let binding = bindings
        .get(parsed.name)
        .ok_or_else(|| format!("bindings.{} not found", parsed.name))?;
    Ok(binding.url.clone())
}
