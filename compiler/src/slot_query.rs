use std::collections::BTreeMap;

use amber_config::stringify_for_interpolation;
pub(crate) use amber_manifest::{SlotQueryError, SlotTarget, parse_slot_query};
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SlotObject {
    pub(crate) url: String,
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
        serde_json::to_value(slots)
            .map_err(|e| format!("failed to serialize {label} as JSON: {e}"))
            .and_then(|value| {
                stringify_for_interpolation(&value)
                    .map_err(|e| format!("failed to stringify {label} for interpolation: {e}"))
            })
    };

    match parsed.target {
        SlotTarget::All => render_object(slots),
        SlotTarget::Slot(slot_name) => {
            let slot = slots
                .get(slot_name)
                .ok_or_else(|| format!("slots.{slot_name} not found"))?;
            let slot_value = serde_json::to_value(slot)
                .map_err(|e| format!("failed to serialize slots.{slot_name} as JSON: {e}"))?;
            let value = query_value_opt(&slot_value, &parsed.path)
                .ok_or_else(|| format!("slots.{query} not found"))?;
            stringify_for_interpolation(value)
                .map_err(|e| format!("failed to stringify slots.{query} for interpolation: {e}"))
        }
    }
}

pub(crate) fn slot_query_is_present(
    slots: &BTreeMap<String, SlotObject>,
    query: &str,
) -> Result<bool, String> {
    let label = if query.is_empty() {
        "slots".to_string()
    } else {
        format!("slots.{query}")
    };

    let parsed =
        parse_slot_query(query).map_err(|err| format!("invalid slot query '{label}': {err}"))?;

    match parsed.target {
        SlotTarget::All => Ok(true),
        SlotTarget::Slot(slot_name) => Ok(slots.get(slot_name).is_some_and(|slot| {
            serde_json::to_value(slot)
                .ok()
                .is_some_and(|value| query_value_opt(&value, &parsed.path).is_some())
        })),
    }
}

fn query_value_opt<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = root;
    for segment in path {
        match current {
            Value::Object(map) => current = map.get(*segment)?,
            _ => return None,
        }
    }
    Some(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_slots() -> BTreeMap<String, SlotObject> {
        BTreeMap::from([(
            "api".to_string(),
            SlotObject {
                url: "https://example.test".to_string(),
            },
        )])
    }

    #[test]
    fn slot_query_presence_checks_the_full_path() {
        let slots = test_slots();

        assert!(slot_query_is_present(&slots, "api").unwrap());
        assert!(slot_query_is_present(&slots, "api.url").unwrap());
        assert!(!slot_query_is_present(&slots, "missing").unwrap());
        assert!(!slot_query_is_present(&slots, "api.url.path").unwrap());
    }

    #[test]
    fn slot_query_resolution_walks_slot_objects() {
        let slots = test_slots();

        assert_eq!(
            resolve_slot_query(&slots, "api.url").unwrap(),
            "https://example.test"
        );
        assert_eq!(
            resolve_slot_query(&slots, "api").unwrap(),
            r#"{"url":"https://example.test"}"#
        );
    }
}
