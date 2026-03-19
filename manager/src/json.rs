use serde_json::Value;

pub(crate) fn merge_json(mut left: Value, right: Value) -> Value {
    merge_json_into(&mut left, right);
    left
}

fn merge_json_into(left: &mut Value, right: Value) {
    match (left, right) {
        (Value::Object(left_obj), Value::Object(right_obj)) => {
            for (key, value) in right_obj {
                merge_json_into(left_obj.entry(key).or_insert(Value::Null), value);
            }
        }
        (slot, value) => *slot = value,
    }
}
