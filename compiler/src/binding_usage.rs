use std::collections::{BTreeSet, HashMap};

use amber_manifest::{InterpolatedPart, InterpolatedString, InterpolationSource};
use amber_scenario::{ComponentId, Scenario};
use serde_json::Value;

use crate::binding_query::parse_binding_query;

#[derive(Clone, Debug, Default)]
pub(crate) struct BindingUsage {
    by_scope: HashMap<ComponentId, BTreeSet<String>>,
}

impl BindingUsage {
    fn record(&mut self, scope: ComponentId, name: &str) {
        self.by_scope
            .entry(scope)
            .or_default()
            .insert(name.to_string());
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&ComponentId, &BTreeSet<String>)> {
        self.by_scope.iter()
    }
}

pub(crate) fn collect_binding_usage(scenario: &Scenario) -> BindingUsage {
    let mut usage = BindingUsage::default();

    for (id, component) in scenario.components_iter() {
        if let Some(program) = component.program.as_ref() {
            if let Ok(image) = program.image.parse::<InterpolatedString>() {
                record_binding_parts(&image.parts, id, &mut usage);
            }
            for arg in &program.args.0 {
                record_binding_parts(&arg.parts, id, &mut usage);
            }
            for value in program.env.values() {
                record_binding_parts(&value.parts, id, &mut usage);
            }
        }

        let scope = component.parent.unwrap_or(id);
        if let Some(config) = component.config.as_ref() {
            record_binding_uses_in_config_value(config, scope, &mut usage);
        }
    }

    usage
}

fn record_binding_parts(parts: &[InterpolatedPart], scope: ComponentId, usage: &mut BindingUsage) {
    for part in parts {
        let InterpolatedPart::Interpolation { source, query } = part else {
            continue;
        };
        if *source != InterpolationSource::Bindings {
            continue;
        }
        if let Ok(parsed) = parse_binding_query(query) {
            usage.record(scope, parsed.name);
        }
    }
}

fn record_binding_uses_in_config_value(
    value: &Value,
    scope: ComponentId,
    usage: &mut BindingUsage,
) {
    match value {
        Value::String(s) => {
            if let Ok(parsed) = s.parse::<InterpolatedString>() {
                record_binding_parts(&parsed.parts, scope, usage);
            }
        }
        Value::Array(values) => {
            for value in values {
                record_binding_uses_in_config_value(value, scope, usage);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                record_binding_uses_in_config_value(value, scope, usage);
            }
        }
        _ => {}
    }
}
