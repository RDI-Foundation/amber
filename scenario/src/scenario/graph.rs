use std::collections::{BTreeSet, VecDeque};

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
/// - Self-bindings and weak edges are ignored for ordering.
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

/// Convenience: compute a stable "path" name for a component like `root/a/b`.
pub fn component_path(s: &Scenario, id: ComponentId) -> String {
    component_path_for(&s.components, id)
}

/// Convenience: compute a stable "path" name for a component like `root/a/b`.
pub fn component_path_for(components: &[Component], id: ComponentId) -> String {
    let mut parts = Vec::new();
    let mut cur = Some(id);
    while let Some(cid) = cur {
        let c = &components[cid.0];
        parts.push(c.name.clone());
        cur = c.parent;
    }
    parts.reverse();
    parts.join("/")
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
    use std::{collections::BTreeMap, sync::Arc};

    use url::Url;

    use super::*;
    use crate::{
        manifest::{DigestAlg, Manifest, ManifestRef},
        scenario::{BindingEdge, Component, ProvideRef, SlotRef},
    };

    fn component(id: usize, name: &str, manifest: Arc<Manifest>) -> Component {
        let url = Url::parse(&format!("file:///component/{name}")).unwrap();
        Component {
            id: ComponentId(id),
            parent: None,
            name: name.to_string(),
            declared_ref: ManifestRef {
                url: url.clone(),
                digest: None,
            },
            resolved_url: url,
            digest: manifest.digest(DigestAlg::Sha256),
            manifest,
            config: None,
            children: BTreeMap::new(),
        }
    }

    #[test]
    fn topo_order_ignores_weak_edges() {
        let manifest = Arc::new(Manifest::empty());
        let components = vec![
            component(0, "a", Arc::clone(&manifest)),
            component(1, "b", Arc::clone(&manifest)),
        ];
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
        let manifest = Arc::new(Manifest::empty());
        let components = vec![
            component(0, "a", Arc::clone(&manifest)),
            component(1, "b", Arc::clone(&manifest)),
            component(2, "c", Arc::clone(&manifest)),
        ];
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
}
