use std::{collections::HashMap, fmt::Write as _};

use amber_manifest::CapabilityKind;
use amber_scenario::{ComponentId, Scenario};

use super::{Reporter, ReporterError};
use crate::CompileOutput;

#[derive(Clone, Copy, Debug, Default)]
pub struct DotReporter;

impl Reporter for DotReporter {
    type Artifact = String;

    fn emit(&self, output: &CompileOutput) -> Result<Self::Artifact, ReporterError> {
        Ok(render_dot_with_exports(output))
    }
}

/// Render a Scenario graph as a Graphviz DOT diagram.
pub fn render_dot(s: &Scenario) -> String {
    render_dot_inner(s, &[])
}

#[derive(Clone, Debug)]
struct ExportEdge {
    endpoint_label: String,
    from: ComponentId,
    kind: CapabilityKind,
}

fn render_dot_with_exports(output: &CompileOutput) -> String {
    let s = &output.scenario;

    let manifests = crate::manifest_table::build_manifest_table(&s.components, &output.store)
        .expect("manifest was resolved during linking");

    let root = s.root;

    let mut id_by_moniker: HashMap<&str, ComponentId> =
        HashMap::with_capacity(output.provenance.components.len());
    for (id, component) in s.components_iter() {
        id_by_moniker.insert(component.moniker.as_str(), id);
    }

    let mut exports = Vec::with_capacity(output.provenance.root_exports.len());
    for export in &output.provenance.root_exports {
        if let Some(&from) = id_by_moniker.get(export.endpoint_component_moniker.as_str()) {
            exports.push(ExportEdge {
                endpoint_label: endpoint_label_for_provide(
                    manifests[from.0].as_ref().expect("manifest should exist"),
                    export.endpoint_provide.as_ref(),
                    export.kind,
                ),
                from,
                kind: export.kind,
            });
            continue;
        }

        exports.push(ExportEdge {
            endpoint_label: format!(
                "<missing export target: {} -> {}.{}>",
                export.name, export.endpoint_component_moniker, export.endpoint_provide
            ),
            from: root,
            kind: export.kind,
        });
    }

    render_dot_inner(s, &exports)
}

fn render_dot_inner(s: &Scenario, exports: &[ExportEdge]) -> String {
    let root = s.root;
    let root_has_program = s.component(root).has_program;
    let root_needs_node = !root_has_program && exports.iter().any(|e| e.from == root);
    let root_has_node = root_has_program || root_needs_node;

    let mut out = String::new();
    let _ = writeln!(out, "digraph scenario {{");
    let _ = writeln!(out, "  rankdir=LR;");
    let _ = writeln!(out, "  compound=true;");

    render_root(s, root_needs_node, 1, &mut out);
    for (id, c) in s.components_iter() {
        if id == root || c.parent.is_some() {
            continue;
        }
        render_component(s, id, 1, &mut out);
    }

    for (i, export) in exports.iter().enumerate() {
        write_indent(&mut out, 1);
        let _ = write!(out, "e{i} [label=\"");
        write_escaped_label(&mut out, &export.endpoint_label);
        let _ = writeln!(out, "\", shape=box];");
    }

    for b in &s.bindings {
        if !root_has_node && (b.from.component == root || b.to.component == root) {
            continue;
        }

        write_indent(&mut out, 1);
        let _ = write!(
            out,
            "c{} -> c{} [label=\"",
            b.from.component.0, b.to.component.0
        );
        write_escaped_label(&mut out, &b.from.name);
        if b.weak {
            let _ = writeln!(out, "\", style=dashed, constraint=false];");
        } else {
            let _ = writeln!(out, "\"];");
        }
    }

    for (i, export) in exports.iter().enumerate() {
        write_indent(&mut out, 1);
        let _ = write!(out, "c{} -> e{i} [label=\"", export.from.0);
        write_escaped_label(&mut out, &export.kind.to_string());
        let _ = writeln!(out, "\"];");
    }

    let _ = writeln!(out, "}}");
    out
}

fn endpoint_label_for_provide(
    manifest: &amber_manifest::Manifest,
    provide_name: &str,
    kind: CapabilityKind,
) -> String {
    let provide = manifest
        .provides()
        .iter()
        .find(|(name, _)| name.as_str() == provide_name)
        .map(|(_, decl)| decl);

    let Some(network) = manifest.program().and_then(|p| p.network.as_ref()) else {
        return "<no network>".to_string();
    };

    let endpoint = if let Some(endpoint_name) = provide.and_then(|p| p.endpoint.as_deref()) {
        network.endpoints.iter().find(|e| e.name == endpoint_name)
    } else if network.endpoints.len() == 1 {
        network.endpoints.iter().next()
    } else if let Some(endpoint) = network.endpoints.iter().find(|e| e.name == provide_name) {
        Some(endpoint)
    } else if kind == CapabilityKind::Llm {
        network
            .endpoints
            .iter()
            .find(|e| e.name == "router")
            .or_else(|| network.endpoints.iter().find(|e| e.name == "endpoint"))
    } else {
        network.endpoints.iter().find(|e| e.name == "endpoint")
    };

    let Some(endpoint) = endpoint else {
        return "<unknown endpoint>".to_string();
    };

    format!("{}:{}{}", endpoint.protocol, endpoint.port, endpoint.path)
}

fn render_root(s: &Scenario, render_root_node: bool, indent: usize, out: &mut String) {
    let root = s.root;
    let c = s.component(root);

    write_indent(out, indent);
    let _ = writeln!(out, "subgraph cluster_{} {{", root.0);
    write_indent(out, indent + 1);
    let _ = writeln!(out, "penwidth=2;");
    write_indent(out, indent + 1);
    let _ = write!(out, "label=\"");
    write_escaped_label(out, c.moniker.as_str());
    let _ = writeln!(out, "\";");

    if c.has_program {
        render_node_with_label(root, "program", indent + 1, out);
    } else if render_root_node {
        render_node(s, root, indent + 1, out);
    }

    for child in &c.children {
        render_component(s, *child, indent + 1, out);
    }

    write_indent(out, indent);
    let _ = writeln!(out, "}}");
}

fn render_component(s: &Scenario, id: ComponentId, indent: usize, out: &mut String) {
    let c = s.component(id);

    if c.children.is_empty() {
        render_node(s, id, indent, out);
        return;
    }

    write_indent(out, indent);
    let _ = writeln!(out, "subgraph cluster_{} {{", id.0);

    write_indent(out, indent + 1);
    let _ = writeln!(out, "penwidth=1;");

    write_indent(out, indent + 1);
    let _ = write!(out, "label=\"");
    write_escaped_label(out, c.moniker.as_str());
    let _ = writeln!(out, "\";");

    render_node(s, id, indent + 1, out);

    for child in &c.children {
        render_component(s, *child, indent + 1, out);
    }

    write_indent(out, indent);
    let _ = writeln!(out, "}}");
}

fn render_node(s: &Scenario, id: ComponentId, indent: usize, out: &mut String) {
    let label = s.component(id).moniker.as_str().to_string();
    render_node_with_label(id, label.as_str(), indent, out);
}

fn render_node_with_label(id: ComponentId, label: &str, indent: usize, out: &mut String) {
    write_indent(out, indent);
    let _ = write!(out, "c{} [label=\"", id.0);
    write_escaped_label(out, label);
    let _ = writeln!(out, "\"];");
}

fn write_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

fn write_escaped_label(out: &mut String, label: &str) {
    for ch in label.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(ch),
        }
    }
}

#[cfg(test)]
mod tests {
    use amber_manifest::{CapabilityKind, Manifest, ManifestDigest, ManifestRef};
    use amber_scenario::{
        BindingEdge, Component, ComponentId, Moniker, ProvideRef, Scenario, SlotRef,
    };
    use url::Url;

    use super::{render_dot, render_dot_with_exports};
    use crate::CompileOutput;

    fn component(id: usize, moniker: &str) -> Component {
        Component {
            id: ComponentId(id),
            parent: None,
            moniker: Moniker::from(moniker.to_string()),
            has_program: false,
            digest: ManifestDigest::new([id as u8; 32]),
            config: None,
            children: Vec::new(),
        }
    }

    #[test]
    fn dot_renders_clusters_and_edges() {
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

        let bindings = vec![
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(1),
                    name: "cap".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(2),
                    name: "needs".to_string(),
                },
                weak: false,
            },
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(2),
                    name: "weak_cap".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(1),
                    name: "opt".to_string(),
                },
                weak: true,
            },
        ];

        let scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings,
        };

        let dot = render_dot(&scenario);
        let expected = r#"digraph scenario {
  rankdir=LR;
  compound=true;
  subgraph cluster_0 {
    penwidth=2;
    label="/";
    subgraph cluster_1 {
      penwidth=1;
      label="/alpha";
      c1 [label="/alpha"];
      c3 [label="/alpha/gamma"];
    }
    c2 [label="/beta"];
  }
  c1 -> c2 [label="cap"];
  c2 -> c1 [label="weak_cap", style=dashed, constraint=false];
}
"#;

        assert_eq!(dot, expected);
    }

    #[test]
    fn dot_renders_root_program_node() {
        let mut components = vec![Some(component(0, "/"))];
        components[0].as_mut().unwrap().has_program = true;

        let scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: Vec::new(),
        };

        let dot = render_dot(&scenario);
        let expected = r#"digraph scenario {
  rankdir=LR;
  compound=true;
  subgraph cluster_0 {
    penwidth=2;
    label="/";
    c0 [label="program"];
  }
}
"#;
        assert_eq!(dot, expected);
    }

    #[test]
    fn dot_renders_root_exports_as_endpoints() {
        let root_manifest = r##"
            {
              manifest_version: "0.1.0",
              runtime: { version: "^1.0.0" },
              components: { a: "a.json5", b: "b.json5" },
              bindings: [
                { to: "#a.in", from: "#b.out" },
              ],
              exports: { public: "#b.out" },
            }
            "##
        .parse::<Manifest>()
        .unwrap();

        let a_manifest = r#"
            {
              manifest_version: "0.1.0",
              runtime: { version: "^1.0.0" },
              slots: { in: { kind: "http" } },
            }
            "#
        .parse::<Manifest>()
        .unwrap();

        let b_manifest = r#"
	            {
	              manifest_version: "0.1.0",
	              runtime: { version: "^1.0.0" },
	              program: {
	                image: "b",
	                network: {
	                  endpoints: [{ name: "ep", port: 8080, path: "/api" }],
	                },
	              },
	              provides: { out: { kind: "http", endpoint: "ep" } },
	              exports: { out: "out" },
	            }
	            "#
        .parse::<Manifest>()
        .unwrap();

        let store = crate::DigestStore::new();
        let root_digest = root_manifest.digest();
        let a_digest = a_manifest.digest();
        let b_digest = b_manifest.digest();

        store.put(root_digest, std::sync::Arc::new(root_manifest));
        store.put(a_digest, std::sync::Arc::new(a_manifest));
        store.put(b_digest, std::sync::Arc::new(b_manifest));

        let mut components = vec![
            Some(component(0, "/")),
            Some(component(1, "/a")),
            Some(component(2, "/b")),
        ];
        components[1].as_mut().unwrap().parent = Some(ComponentId(0));
        components[2].as_mut().unwrap().parent = Some(ComponentId(0));
        components[0].as_mut().unwrap().digest = root_digest;
        components[1].as_mut().unwrap().digest = a_digest;
        components[2].as_mut().unwrap().digest = b_digest;

        components[0]
            .as_mut()
            .unwrap()
            .children
            .extend([ComponentId(1), ComponentId(2)]);

        let scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: vec![BindingEdge {
                from: ProvideRef {
                    component: ComponentId(2),
                    name: "out".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(1),
                    name: "in".to_string(),
                },
                weak: false,
            }],
        };

        let url = Url::parse("file:///scenario.json5").unwrap();
        let output = CompileOutput {
            scenario,
            store,
            provenance: crate::Provenance {
                components: vec![
                    crate::ComponentProvenance {
                        authored_moniker: Moniker::from("/".to_string()),
                        declared_ref: ManifestRef::from_url(url.clone()),
                        resolved_url: url.clone(),
                        digest: root_digest,
                        observed_url: None,
                    },
                    crate::ComponentProvenance {
                        authored_moniker: Moniker::from("/a".to_string()),
                        declared_ref: ManifestRef::from_url(url.clone()),
                        resolved_url: url.clone(),
                        digest: a_digest,
                        observed_url: None,
                    },
                    crate::ComponentProvenance {
                        authored_moniker: Moniker::from("/b".to_string()),
                        declared_ref: ManifestRef::from_url(url.clone()),
                        resolved_url: url,
                        digest: b_digest,
                        observed_url: None,
                    },
                ],
                root_exports: vec![crate::RootExportProvenance {
                    name: std::sync::Arc::from("public"),
                    endpoint_component_moniker: Moniker::from("/b".to_string()),
                    endpoint_provide: std::sync::Arc::from("out"),
                    kind: CapabilityKind::Http,
                }],
            },
            diagnostics: Vec::new(),
        };

        let dot = render_dot_with_exports(&output);
        let expected = r#"digraph scenario {
  rankdir=LR;
  compound=true;
  subgraph cluster_0 {
    penwidth=2;
    label="/";
    c1 [label="/a"];
    c2 [label="/b"];
  }
  e0 [label="http:8080/api", shape=box];
  c2 -> c1 [label="out"];
  c2 -> e0 [label="http"];
}
"#;

        assert_eq!(dot, expected);
    }

    #[test]
    fn dot_renders_missing_export_target_as_placeholder() {
        let root_manifest = r#"
            {
              manifest_version: "0.1.0",
              runtime: { version: "^1.0.0" },
              components: { a: "a.json5" },
            }
            "#
        .parse::<Manifest>()
        .unwrap();

        let a_manifest = r#"
            {
              manifest_version: "0.1.0",
              runtime: { version: "^1.0.0" },
              provides: { out: { kind: "http" } },
              exports: { out: "out" },
            }
            "#
        .parse::<Manifest>()
        .unwrap();

        let store = crate::DigestStore::new();
        let root_digest = root_manifest.digest();
        let a_digest = a_manifest.digest();
        store.put(root_digest, std::sync::Arc::new(root_manifest));
        store.put(a_digest, std::sync::Arc::new(a_manifest));

        let mut components = vec![Some(component(0, "/")), Some(component(1, "/a"))];
        components[1].as_mut().unwrap().parent = Some(ComponentId(0));
        components[0].as_mut().unwrap().digest = root_digest;
        components[1].as_mut().unwrap().digest = a_digest;

        components[0]
            .as_mut()
            .unwrap()
            .children
            .push(ComponentId(1));

        let scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: Vec::new(),
        };

        let url = Url::parse("file:///scenario.json5").unwrap();
        let output = CompileOutput {
            scenario,
            store,
            provenance: crate::Provenance {
                components: vec![
                    crate::ComponentProvenance {
                        authored_moniker: Moniker::from("/".to_string()),
                        declared_ref: ManifestRef::from_url(url.clone()),
                        resolved_url: url.clone(),
                        digest: root_digest,
                        observed_url: None,
                    },
                    crate::ComponentProvenance {
                        authored_moniker: Moniker::from("/a".to_string()),
                        declared_ref: ManifestRef::from_url(url.clone()),
                        resolved_url: url,
                        digest: a_digest,
                        observed_url: None,
                    },
                ],
                root_exports: vec![crate::RootExportProvenance {
                    name: std::sync::Arc::from("public"),
                    endpoint_component_moniker: Moniker::from("/missing".to_string()),
                    endpoint_provide: std::sync::Arc::from("out"),
                    kind: CapabilityKind::Http,
                }],
            },
            diagnostics: Vec::new(),
        };

        let dot = render_dot_with_exports(&output);
        assert!(dot.contains("<missing export target: public -> /missing.out>"));
        assert!(dot.contains("c0 -> e0 [label=\"http\"]"));
    }
}
