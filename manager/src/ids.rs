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
    format!("svc_{}_{}", scenario_id, sanitize_component(export_name))
}

pub fn operator_service_id(name: &str) -> String {
    format!("svc_{}", sanitize_component(name))
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
