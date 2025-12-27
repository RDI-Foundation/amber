use std::{
    collections::{BTreeSet, VecDeque},
    fmt::Write as _,
};

use super::{Component, ComponentId, Scenario};

#[derive(Clone, Debug, thiserror::Error)]
#[error("scenario contains a dependency cycle: {cycle:?}")]
pub struct CycleError {
    pub cycle: Vec<ComponentId>,
}

/// Topologically sort components by binding dependencies:
/// if A provides something bound into B's slot, A must come before B.
///
/// Notes:
/// - Self-bindings are ignored.
/// - Weak edges are ignored for ordering and cycle detection (they can point "backwards" without creating a dependency cycle).
/// - This is intentionally separate from Scenario (graph ops live here).
pub fn topo_order(s: &Scenario) -> Result<Vec<ComponentId>, CycleError> {
    let n = s.components.len();
    let mut indeg = vec![0usize; n];
    let mut out: Vec<Vec<usize>> = vec![Vec::new(); n];

    for b in &s.bindings {
        if b.weak {
            continue;
        }
        let u = b.from.component.0;
        let v = b.to.component.0;
        if u == v {
            continue;
        }
        out[u].push(v);
    }

    for out in &mut out {
        out.sort_unstable();
        out.dedup();
        for &v in out.iter() {
            indeg[v] += 1;
        }
    }

    let mut q = VecDeque::new();
    for (i, &d) in indeg.iter().enumerate() {
        if d == 0 {
            q.push_back(i);
        }
    }

    let mut order = Vec::with_capacity(n);
    while let Some(u) = q.pop_front() {
        order.push(ComponentId(u));
        for &v in &out[u] {
            indeg[v] -= 1;
            if indeg[v] == 0 {
                q.push_back(v);
            }
        }
    }

    if order.len() == n {
        return Ok(order);
    }

    let cycle = find_cycle(&out, &indeg);
    Err(CycleError { cycle })
}

/// Convenience: compute a stable "path" name for a component like `/a/b`.
pub fn component_path(s: &Scenario, id: ComponentId) -> String {
    component_path_for(&s.components, id)
}

/// Convenience: compute a stable "path" name for a component like `/a/b`.
pub fn component_path_for(components: &[Component], id: ComponentId) -> String {
    let mut parts = Vec::new();
    let mut cur = Some(id);
    while let Some(cid) = cur {
        let c = &components[cid.0];
        if c.parent.is_some() {
            parts.push(c.name.as_str());
        }
        cur = c.parent;
    }

    if parts.is_empty() {
        return "/".to_string();
    }

    let len = parts.iter().map(|p| p.len()).sum::<usize>() + parts.len();
    let mut out = String::with_capacity(len);
    out.push('/');
    for (i, part) in parts.iter().rev().enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(part);
    }
    out
}

/// Convenience: list direct dependencies (providers) of a component, by id.
pub fn providers_of(s: &Scenario, id: ComponentId) -> BTreeSet<ComponentId> {
    let mut set = BTreeSet::new();
    for b in &s.bindings {
        if b.to.component == id && b.from.component != id {
            set.insert(b.from.component);
        }
    }
    set
}

/// Render the Scenario graph as a Graphviz DOT diagram.
pub fn to_dot(s: &Scenario) -> String {
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

fn find_cycle(out: &[Vec<usize>], indeg: &[usize]) -> Vec<ComponentId> {
    let n = out.len();
    let mut state = vec![0u8; n];
    let mut stack = Vec::new();

    fn dfs(
        u: usize,
        out: &[Vec<usize>],
        indeg: &[usize],
        state: &mut [u8],
        stack: &mut Vec<usize>,
    ) -> Option<Vec<usize>> {
        state[u] = 1;
        stack.push(u);

        for &v in &out[u] {
            if indeg[v] == 0 {
                continue;
            }
            match state[v] {
                0 => {
                    if let Some(cycle) = dfs(v, out, indeg, state, stack) {
                        return Some(cycle);
                    }
                }
                1 => {
                    let start = stack
                        .iter()
                        .position(|&node| node == v)
                        .expect("node on stack");
                    let mut cycle = stack[start..].to_vec();
                    cycle.push(v);
                    return Some(cycle);
                }
                _ => {}
            }
        }

        stack.pop();
        state[u] = 2;
        None
    }

    for u in 0..n {
        if indeg[u] == 0 || state[u] != 0 {
            continue;
        }
        if let Some(cycle) = dfs(u, out, indeg, &mut state, &mut stack) {
            return cycle.into_iter().map(ComponentId).collect();
        }
    }

    unreachable!("cycle expected in remaining graph");
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use amber_manifest::ManifestDigest;

    use super::*;
    use crate::{BindingEdge, ProvideRef, SlotRef};

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
    fn topo_order_ignores_weak_edges() {
        let components = vec![component(0, "a"), component(1, "b")];
        let bindings = vec![
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(0),
                    name: "api".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(1),
                    name: "needs".to_string(),
                },
                weak: false,
            },
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(1),
                    name: "api".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(0),
                    name: "needs".to_string(),
                },
                weak: true,
            },
        ];
        let scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings,
        };

        let order = topo_order(&scenario).unwrap();
        assert_eq!(order, vec![ComponentId(0), ComponentId(1)]);
    }

    #[test]
    fn topo_order_reports_cycle_path() {
        let components = vec![component(0, "a"), component(1, "b"), component(2, "c")];
        let bindings = vec![
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(0),
                    name: "p".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(1),
                    name: "s".to_string(),
                },
                weak: false,
            },
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(1),
                    name: "p".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(2),
                    name: "s".to_string(),
                },
                weak: false,
            },
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(2),
                    name: "p".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(0),
                    name: "s".to_string(),
                },
                weak: false,
            },
        ];
        let scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings,
        };

        let cycle = topo_order(&scenario).unwrap_err().cycle;
        assert!(cycle.len() > 1);
        assert_eq!(cycle.first(), cycle.last());
        for pair in cycle.windows(2) {
            let from = pair[0];
            let to = pair[1];
            assert!(
                scenario
                    .bindings
                    .iter()
                    .any(|b| !b.weak && b.from.component == from && b.to.component == to),
                "missing edge {from:?} -> {to:?}"
            );
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

        let dot = to_dot(&scenario);
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

        let dot = to_dot(&scenario);
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
