pub(crate) mod query;
mod validation;

pub(crate) use query::{
    SlotObject, SlotQueryError, SlotTarget, SlotValue, parse_slot_query, resolve_slot_query,
    slot_query_is_present,
};
pub(crate) use validation::collect_slot_interpolation_diagnostics_from_tree;
