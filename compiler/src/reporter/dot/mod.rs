use std::fmt::Write as _;

use amber_manifest::CapabilityKind;
use amber_scenario::{BindingFrom, Component, ComponentId, Scenario};

use super::{Reporter, ReporterError};

#[derive(Clone, Copy, Debug, Default)]
pub struct DotReporter;

impl Reporter for DotReporter {
    type Artifact = String;

    fn emit(&self, scenario: &Scenario) -> Result<Self::Artifact, ReporterError> {
        Ok(render_dot_with_exports(scenario))
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

fn render_dot_with_exports(s: &Scenario) -> String {
    let mut exports = Vec::with_capacity(s.exports.len());
    for export in &s.exports {
        let from = export.from.component;
        let kind = export.capability.kind;
        exports.push(ExportEdge {
            endpoint_label: endpoint_label_for_provide(
                s.component(from),
                export.from.name.as_str(),
            ),
            from,
            kind,
        });
    }

    render_dot_inner(s, &exports)
}

fn render_dot_inner(s: &Scenario, exports: &[ExportEdge]) -> String {
    let root = s.root;
    let root_has_program = s.component(root).program.is_some();
    let root_has_binding = s.bindings.iter().any(|b| {
        matches!(&b.from, BindingFrom::Component(from) if from.component == root)
            || b.to.component == root
    });
    let root_needs_node =
        !root_has_program && (exports.iter().any(|e| e.from == root) || root_has_binding);
    let root_has_node = root_has_program || root_needs_node;
    let has_framework = s
        .bindings
        .iter()
        .any(|b| matches!(b.from, BindingFrom::Framework(_)));
    let has_external = s
        .bindings
        .iter()
        .any(|b| matches!(b.from, BindingFrom::External(_)));

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
    if has_framework {
        write_indent(&mut out, 1);
        let _ = writeln!(out, "framework [label=\"framework\", shape=box];");
    }
    if has_external {
        write_indent(&mut out, 1);
        let _ = writeln!(out, "external [label=\"external\", shape=box];");
    }

    for b in &s.bindings {
        let from_component = match &b.from {
            BindingFrom::Component(from) => Some(from.component),
            BindingFrom::Framework(_) => None,
            BindingFrom::External(_) => None,
        };
        if !root_has_node && (from_component == Some(root) || b.to.component == root) {
            continue;
        }

        write_indent(&mut out, 1);
        match &b.from {
            BindingFrom::Component(from) => {
                let _ = write!(
                    out,
                    "c{} -> c{} [label=\"",
                    from.component.0, b.to.component.0
                );
                write_escaped_label(&mut out, &from.name);
            }
            BindingFrom::Framework(name) => {
                let _ = write!(out, "framework -> c{} [label=\"", b.to.component.0);
                write_escaped_label(&mut out, &format!("framework.{name}"));
            }
            BindingFrom::External(slot) => {
                let _ = write!(out, "external -> c{} [label=\"", b.to.component.0);
                write_escaped_label(&mut out, &format!("slots.{}", slot.name));
            }
        }
        if let Some(name) = b.name.as_ref() {
            let _ = write!(out, " (");
            write_escaped_label(&mut out, name);
            let _ = write!(out, ")");
        }
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

fn endpoint_label_for_provide(component: &Component, provide_name: &str) -> String {
    let provide = component
        .provides
        .get(provide_name)
        .expect("scenario invariant: provide exists");

    let network = component
        .program
        .as_ref()
        .and_then(|p| p.network.as_ref())
        .expect("scenario invariant: provide requires a network");

    let endpoint_name = provide
        .endpoint
        .as_deref()
        .expect("scenario invariant: provide declares an endpoint");

    let endpoint = network
        .endpoints
        .iter()
        .find(|e| e.name == endpoint_name)
        .expect("scenario invariant: endpoint exists");

    format!("{}:{}", endpoint.protocol, endpoint.port)
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

    if c.program.is_some() {
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
mod tests;
