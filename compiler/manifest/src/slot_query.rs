use std::fmt;

use crate::SlotDecl;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotTarget<'a> {
    All,
    Slot(&'a str),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotQuery<'a> {
    pub target: SlotTarget<'a>,
    pub path: Vec<&'a str>,
}

#[derive(Debug)]
pub enum SlotQueryError {
    MissingSlotName,
    EmptySegment { query: String },
    UnknownField { field: String },
    UnknownPath { path: String },
}

impl fmt::Display for SlotQueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SlotQueryError::MissingSlotName => {
                f.write_str("missing slot name (expected slots.<slot>)")
            }
            SlotQueryError::EmptySegment { query } => {
                write!(f, "invalid slots path {query:?}: empty segment")
            }
            SlotQueryError::UnknownField { field } => {
                write!(f, "unknown slot field {field:?}")
            }
            SlotQueryError::UnknownPath { path } => {
                write!(f, "unknown slot path {path:?}")
            }
        }
    }
}

pub fn parse_slot_query(query: &str) -> Result<SlotQuery<'_>, SlotQueryError> {
    if query.is_empty() {
        return Ok(SlotQuery {
            target: SlotTarget::All,
            path: Vec::new(),
        });
    }

    let mut segments = query.split('.');
    let slot = segments
        .next()
        .expect("split on '.' always yields at least one segment");
    if slot.is_empty() {
        return Err(SlotQueryError::MissingSlotName);
    }

    let rest: Vec<&str> = segments.collect();
    if rest.iter().any(|seg| seg.is_empty()) {
        return Err(SlotQueryError::EmptySegment {
            query: query.to_string(),
        });
    }

    Ok(SlotQuery {
        target: SlotTarget::Slot(slot),
        path: rest,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotQueryValidation {
    pub guaranteed_when_slot_is_bound: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotValueShape {
    Scalar,
    UrlObject,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SlotFieldShape {
    optional: bool,
    value: SlotValueShape,
}

fn slot_root_shape(_slot: &SlotDecl) -> SlotValueShape {
    // All current slot kinds expose a URL-shaped object. Extend this when slot value schemas grow.
    SlotValueShape::UrlObject
}

fn descend_slot_shape(shape: SlotValueShape, segment: &str) -> Option<SlotFieldShape> {
    match shape {
        SlotValueShape::Scalar => None,
        SlotValueShape::UrlObject => (segment == "url").then_some(SlotFieldShape {
            optional: false,
            value: SlotValueShape::Scalar,
        }),
    }
}

pub fn validate_slot_query_for_slot(
    slot: &SlotDecl,
    query: &SlotQuery<'_>,
) -> Result<SlotQueryValidation, SlotQueryError> {
    let SlotTarget::Slot(_) = query.target else {
        return Ok(SlotQueryValidation {
            guaranteed_when_slot_is_bound: true,
        });
    };

    let mut guaranteed_when_slot_is_bound = true;
    let mut shape = slot_root_shape(slot);
    for (idx, segment) in query.path.iter().enumerate() {
        let Some(field) = descend_slot_shape(shape, segment) else {
            return Err(if idx + 1 == query.path.len() {
                SlotQueryError::UnknownField {
                    field: (*segment).to_string(),
                }
            } else {
                SlotQueryError::UnknownPath {
                    path: query.path[idx..].join("."),
                }
            });
        };
        guaranteed_when_slot_is_bound &= !field.optional;
        shape = field.value;
    }

    Ok(SlotQueryValidation {
        guaranteed_when_slot_is_bound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityDecl, CapabilityKind};

    #[test]
    fn slot_query_accepts_slot_and_nested_path() {
        let whole = parse_slot_query("api").unwrap();
        assert_eq!(whole.target, SlotTarget::Slot("api"));
        assert!(whole.path.is_empty());

        let url = parse_slot_query("api.url").unwrap();
        assert_eq!(url.target, SlotTarget::Slot("api"));
        assert_eq!(url.path, vec!["url"]);
    }

    #[test]
    fn slot_query_rejects_empty_segment() {
        let err = parse_slot_query("api..url").unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid slots path \"api..url\": empty segment"
        );
    }

    #[test]
    fn slot_query_validation_uses_slot_shape() {
        let slot = SlotDecl {
            decl: CapabilityDecl {
                kind: CapabilityKind::Http,
                profile: None,
            },
            optional: false,
            multiple: false,
        };

        let query = parse_slot_query("api.url").unwrap();
        assert_eq!(
            validate_slot_query_for_slot(&slot, &query).unwrap(),
            SlotQueryValidation {
                guaranteed_when_slot_is_bound: true
            }
        );

        let bad = parse_slot_query("api.blabla").unwrap();
        assert_eq!(
            validate_slot_query_for_slot(&slot, &bad)
                .unwrap_err()
                .to_string(),
            "unknown slot field \"blabla\""
        );

        let bad_path = parse_slot_query("api.blabla.more").unwrap();
        assert_eq!(
            validate_slot_query_for_slot(&slot, &bad_path)
                .unwrap_err()
                .to_string(),
            "unknown slot path \"blabla.more\""
        );
    }
}
