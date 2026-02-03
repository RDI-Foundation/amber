use std::collections::BTreeMap;

use amber_scenario::Scenario;
use serde_json::Value;

use super::{Reporter, ReporterError};
use crate::CompileOutput;

#[derive(Clone, Copy, Debug, Default)]
pub struct MetadataReporter;

impl Reporter for MetadataReporter {
    type Artifact = String;

    fn emit(&self, output: &CompileOutput) -> Result<Self::Artifact, ReporterError> {
        render_metadata(&output.scenario)
    }
}

/// Render user-provided component metadata keyed by component moniker.
pub fn render_metadata(s: &Scenario) -> Result<String, ReporterError> {
    let metadata = collect_metadata(s);
    let mut out = serde_json::to_string_pretty(&metadata)
        .map_err(|e| ReporterError::new(format!("failed to render metadata: {e}")))?;
    out.push('\n');
    Ok(out)
}

fn collect_metadata(s: &Scenario) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    let mut stack = vec![s.root];

    while let Some(id) = stack.pop() {
        let component = s.component(id);
        if let Some(metadata) = component.metadata.clone() {
            out.insert(component.moniker.as_str().to_string(), metadata);
        }

        for child in component.children.iter().rev() {
            stack.push(*child);
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use amber_manifest::ManifestDigest;
    use amber_scenario::{Component, ComponentId, Moniker, Scenario};
    use serde_json::json;

    use super::render_metadata;

    fn component(id: usize, moniker: &str) -> Component {
        Component {
            id: ComponentId(id),
            parent: None,
            moniker: Moniker::from(moniker.to_string()),
            digest: ManifestDigest::new([id as u8; 32]),
            config: None,
            program: None,
            slots: BTreeMap::new(),
            provides: BTreeMap::new(),
            metadata: None,
            children: Vec::new(),
        }
    }

    #[test]
    fn renders_flat_metadata_map() {
        let mut components = vec![
            Some(component(0, "/")),
            Some(component(1, "/alpha")),
            Some(component(2, "/beta")),
            Some(component(3, "/alpha/gamma")),
        ];

        components[1].as_mut().unwrap().parent = Some(ComponentId(0));
        components[2].as_mut().unwrap().parent = Some(ComponentId(0));
        components[3].as_mut().unwrap().parent = Some(ComponentId(1));

        components[0]
            .as_mut()
            .unwrap()
            .children
            .extend([ComponentId(1), ComponentId(2)]);
        components[1]
            .as_mut()
            .unwrap()
            .children
            .push(ComponentId(3));

        components[0].as_mut().unwrap().metadata = Some(json!({ "root": true }));
        components[3].as_mut().unwrap().metadata = Some(json!("leaf"));

        let scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: Vec::new(),
            exports: Vec::new(),
        };

        let rendered = render_metadata(&scenario).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let expected = json!({
            "/": { "root": true },
            "/alpha/gamma": "leaf",
        });
        assert_eq!(value, expected);
    }
}
