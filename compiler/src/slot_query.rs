use std::{collections::BTreeMap, fmt};

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SlotObject {
    pub(crate) url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotField {
    Whole,
    Url,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotTarget<'a> {
    All,
    Slot(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SlotQuery<'a> {
    pub(crate) target: SlotTarget<'a>,
    pub(crate) field: SlotField,
}

#[derive(Debug)]
pub(crate) enum SlotQueryError {
    MissingSlotName,
    EmptySegment { query: String },
    UnsupportedField { field: String },
    UnsupportedPath { path: String },
}

impl fmt::Display for SlotQueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlotQueryError::MissingSlotName => {
                f.write_str("missing slot name (expected slots.<slot> or slots.<slot>.url)")
            }
            SlotQueryError::EmptySegment { query } => {
                write!(f, "invalid slots path {query:?}: empty segment")
            }
            SlotQueryError::UnsupportedField { field } => write!(
                f,
                "unsupported slots field {field:?} (only \"url\" is supported)"
            ),
            SlotQueryError::UnsupportedPath { path } => write!(
                f,
                "unsupported slots path {path:?} (only \"url\" is supported)"
            ),
        }
    }
}

pub(crate) fn parse_slot_query(query: &str) -> Result<SlotQuery<'_>, SlotQueryError> {
    if query.is_empty() {
        return Ok(SlotQuery {
            target: SlotTarget::All,
            field: SlotField::Whole,
        });
    }

    let mut segments = query.split('.');
    let slot = segments.next().unwrap_or_default();
    if slot.is_empty() {
        return Err(SlotQueryError::MissingSlotName);
    }

    let rest: Vec<&str> = segments.collect();
    if rest.iter().any(|seg| seg.is_empty()) {
        return Err(SlotQueryError::EmptySegment {
            query: query.to_string(),
        });
    }

    let field = match rest.as_slice() {
        [] => SlotField::Whole,
        ["url"] => SlotField::Url,
        [other] => {
            return Err(SlotQueryError::UnsupportedField {
                field: (*other).to_string(),
            });
        }
        _ => {
            return Err(SlotQueryError::UnsupportedPath {
                path: rest.join("."),
            });
        }
    };

    Ok(SlotQuery {
        target: SlotTarget::Slot(slot),
        field,
    })
}

pub(crate) fn resolve_slot_query(
    slots: &BTreeMap<String, SlotObject>,
    query: &str,
) -> Result<String, String> {
    let label = if query.is_empty() {
        "slots".to_string()
    } else {
        format!("slots.{query}")
    };

    let parsed = parse_slot_query(query)
        .map_err(|err| format!("invalid slots interpolation '{label}': {err}"))?;

    let render_object = |slots: &BTreeMap<String, SlotObject>| {
        serde_json::to_string(slots)
            .map_err(|e| format!("failed to serialize {label} as JSON: {e}"))
    };

    match parsed.target {
        SlotTarget::All => render_object(slots),
        SlotTarget::Slot(slot_name) => {
            let slot = slots
                .get(slot_name)
                .ok_or_else(|| format!("slots.{slot_name} not found"))?;
            match parsed.field {
                SlotField::Whole => serde_json::to_string(slot)
                    .map_err(|e| format!("failed to serialize slots.{slot_name} as JSON: {e}")),
                SlotField::Url => Ok(slot.url.clone()),
            }
        }
    }
}
