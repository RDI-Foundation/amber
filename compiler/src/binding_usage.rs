use std::collections::{BTreeSet, HashMap, HashSet};

use amber_manifest::{InterpolatedPart, InterpolatedString, InterpolationSource};
use amber_scenario::{ComponentId, Scenario};
use serde_json::Value;

use crate::binding_query::parse_binding_query;

#[derive(Clone, Debug, Default)]
pub(crate) struct BindingUsage {
    by_scope: HashMap<ComponentId, BTreeSet<String>>,
    by_component: HashMap<ComponentId, HashSet<BindingUse>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum BindingUseSource {
    Program,
    Config,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct BindingUse {
    pub(crate) source: BindingUseSource,
    pub(crate) scope: ComponentId,
    pub(crate) name: String,
}

impl BindingUsage {
    fn record(
        &mut self,
        component: ComponentId,
        source: BindingUseSource,
        scope: ComponentId,
        name: &str,
    ) {
        self.by_scope
            .entry(scope)
            .or_default()
            .insert(name.to_string());
        self.by_component
            .entry(component)
            .or_default()
            .insert(BindingUse {
                source,
                scope,
                name: name.to_string(),
            });
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&ComponentId, &BTreeSet<String>)> {
        self.by_scope.iter()
    }

    pub(crate) fn for_component(
        &self,
        component: ComponentId,
    ) -> impl Iterator<Item = &BindingUse> {
        self.by_component
            .get(&component)
            .into_iter()
            .flat_map(|uses| uses.iter())
    }

    pub(crate) fn for_component_with_source(
        &self,
        component: ComponentId,
        source: BindingUseSource,
    ) -> impl Iterator<Item = &BindingUse> {
        self.for_component(component)
            .filter(move |binding_use| binding_use.source == source)
    }
}

pub(crate) fn collect_binding_usage(scenario: &Scenario) -> BindingUsage {
    let mut usage = BindingUsage::default();

    for (id, component) in scenario.components_iter() {
        if let Some(program) = component.program.as_ref() {
            if let Ok(image) = program.image.parse::<InterpolatedString>() {
                record_binding_parts(&image.parts, id, BindingUseSource::Program, id, &mut usage);
            }
            for arg in &program.args.0 {
                record_binding_parts(&arg.parts, id, BindingUseSource::Program, id, &mut usage);
            }
            for value in program.env.values() {
                record_binding_parts(&value.parts, id, BindingUseSource::Program, id, &mut usage);
            }
        }

        let scope = component.parent.unwrap_or(id);
        if let Some(config) = component.config.as_ref() {
            record_binding_uses_in_config_value(
                config,
                id,
                BindingUseSource::Config,
                scope,
                &mut usage,
            );
        }
    }

    usage
}

fn record_binding_parts(
    parts: &[InterpolatedPart],
    component: ComponentId,
    usage_source: BindingUseSource,
    scope: ComponentId,
    usage: &mut BindingUsage,
) {
    for part in parts {
        let InterpolatedPart::Interpolation { source, query } = part else {
            continue;
        };
        if *source != InterpolationSource::Bindings {
            continue;
        }
        if let Ok(parsed) = parse_binding_query(query) {
            usage.record(component, usage_source, scope, parsed.name);
        }
    }
}

fn record_binding_uses_in_config_value(
    value: &Value,
    component: ComponentId,
    usage_source: BindingUseSource,
    scope: ComponentId,
    usage: &mut BindingUsage,
) {
    match value {
        Value::String(s) => {
            if let Ok(parsed) = s.parse::<InterpolatedString>() {
                record_binding_parts(&parsed.parts, component, usage_source, scope, usage);
            }
        }
        Value::Array(values) => {
            for value in values {
                record_binding_uses_in_config_value(value, component, usage_source, scope, usage);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                record_binding_uses_in_config_value(value, component, usage_source, scope, usage);
            }
        }
        _ => {}
    }
}
