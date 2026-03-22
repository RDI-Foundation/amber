use uuid::Uuid;

pub fn new_scenario_id() -> String {
    format!("scn_{}", Uuid::now_v7().simple())
}

pub fn new_operation_id() -> String {
    format!("op_{}", Uuid::now_v7().simple())
}

pub fn compose_project_name(scenario_id: &str) -> String {
    format!("amber_{}", scenario_id.replace('-', "_"))
}

pub fn export_service_id(scenario_id: &str, export_name: &str) -> String {
    format!("svc_{}_{}", scenario_id, hex_encode_component(export_name))
}

pub fn operator_service_id(name: &str) -> String {
    format!("svc_{}", sanitize_component(name))
}

pub fn operator_config_id(name: &str) -> String {
    format!("cfg_{}", sanitize_component(name))
}

fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn hex_encode_component(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let bytes = value.as_bytes();
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::export_service_id;

    #[test]
    fn export_service_ids_preserve_distinct_names() {
        assert_ne!(
            export_service_id("scn_test", "api-prod"),
            export_service_id("scn_test", "api_prod")
        );
        assert_ne!(
            export_service_id("scn_test", "API"),
            export_service_id("scn_test", "api")
        );
    }
}
