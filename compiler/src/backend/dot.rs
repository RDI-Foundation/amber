use std::fmt::Write as _;

use amber_scenario::{ComponentId, Scenario, graph::component_path_for};

use super::{Backend, BackendError};
use crate::CompileOutput;

#[derive(Clone, Copy, Debug, Default)]
pub struct DotBackend;

impl Backend for DotBackend {
    type Artifact = String;

    fn emit(&self, output: &CompileOutput) -> Result<Self::Artifact, BackendError> {
        Ok(render_dot(&output.scenario))
    }
}

/// Render a Scenario graph as a Graphviz DOT diagram.
pub fn render_dot(s: &Scenario) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "digraph scenario {{");
    let _ = writeln!(out, "  rankdir=LR;");
    let _ = writeln!(out, "  compound=true;");
    let root = s.root;
    render_root(s, 1, &mut out);
    for (id, c) in s.components.iter().enumerate() {
        let id = ComponentId(id);
        if id == root || c.parent.is_some() {
            continue;
        }
        render_component(s, id, 1, &mut out);
    }

    let root_has_program = s.components[root.0].has_program;
    for b in &s.bindings {
        if !root_has_program && (b.from.component == root || b.to.component == root) {
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

    let _ = writeln!(out, "}}");
    out
}

fn render_root(s: &Scenario, indent: usize, out: &mut String) {
    let root = s.root;
    let c = &s.components[root.0];

    write_indent(out, indent);
    let _ = writeln!(out, "subgraph cluster_{} {{", root.0);
    write_indent(out, indent + 1);
    let _ = writeln!(out, "penwidth=2;");
    write_indent(out, indent + 1);
    if c.name.is_empty() {
        let _ = writeln!(out, "label=\"\";");
    } else {
        let _ = write!(out, "label=\"");
        write_escaped_label(out, &c.name);
        let _ = writeln!(out, "\";");
    }

    if c.has_program {
        render_node_with_label(root, "program", indent + 1, out);
    }

    for child in c.children.values() {
        render_component(s, *child, indent + 1, out);
    }

    write_indent(out, indent);
    let _ = writeln!(out, "}}");
}

fn render_component(s: &Scenario, id: ComponentId, indent: usize, out: &mut String) {
    let c = &s.components[id.0];

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
    write_escaped_label(out, &c.name);
    let _ = writeln!(out, "\";");

    render_node(s, id, indent + 1, out);

    for child in c.children.values() {
        render_component(s, *child, indent + 1, out);
    }

    write_indent(out, indent);
    let _ = writeln!(out, "}}");
}

fn render_node(s: &Scenario, id: ComponentId, indent: usize, out: &mut String) {
    let label = component_path_for(&s.components, id);
    render_node_with_label(id, &label, indent, out);
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
    use std::collections::BTreeMap;

    use amber_manifest::ManifestDigest;
    use amber_scenario::{BindingEdge, Component, ComponentId, ProvideRef, Scenario, SlotRef};

    use super::render_dot;

    fn component(id: usize, name: &str) -> Component {
        Component {
            id: ComponentId(id),
            parent: None,
            name: name.to_string(),
            has_program: false,
            digest: ManifestDigest::new([id as u8; 32]),
            config: None,
            children: BTreeMap::new(),
        }
    }

    #[test]
    fn dot_renders_clusters_and_edges() {
        let mut components = vec![
            component(0, ""),
            component(1, "alpha"),
            component(2, "beta"),
            component(3, "gamma"),
        ];
        components[1].parent = Some(ComponentId(0));
        components[2].parent = Some(ComponentId(0));
        components[3].parent = Some(ComponentId(1));

        let mut root_children = BTreeMap::new();
        root_children.insert("alpha".to_string(), ComponentId(1));
        root_children.insert("beta".to_string(), ComponentId(2));
        components[0].children = root_children;

        let mut alpha_children = BTreeMap::new();
        alpha_children.insert("gamma".to_string(), ComponentId(3));
        components[1].children = alpha_children;

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
    label="";
    subgraph cluster_1 {
      penwidth=1;
      label="alpha";
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
        let mut components = vec![component(0, "")];
        components[0].has_program = true;

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
    label="";
    c0 [label="program"];
  }
}
"#;
        assert_eq!(dot, expected);
    }
}
