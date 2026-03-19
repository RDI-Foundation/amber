use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::store::{StoredDependency, StoredScenario};

#[derive(Clone, Debug, Default)]
pub(super) struct ScenarioGraph {
    edges: BTreeMap<String, BTreeSet<String>>,
    in_degree: BTreeMap<String, usize>,
}

impl ScenarioGraph {
    pub(super) fn new(nodes: impl IntoIterator<Item = String>) -> Self {
        let mut graph = Self::default();
        for node in nodes {
            graph.in_degree.entry(node).or_insert(0);
        }
        graph
    }

    pub(super) fn add_edge(&mut self, provider: String, consumer: String) -> bool {
        self.in_degree.entry(provider.clone()).or_insert(0);
        self.in_degree.entry(consumer.clone()).or_insert(0);
        let inserted = self
            .edges
            .entry(provider)
            .or_default()
            .insert(consumer.clone());
        if inserted {
            *self
                .in_degree
                .get_mut(&consumer)
                .expect("consumer should exist") += 1;
        }
        inserted
    }

    pub(super) fn is_acyclic(&self) -> bool {
        self.clone().walk().visited == self.in_degree.len()
    }

    pub(super) fn ordered(self) -> Vec<String> {
        let TopologyWalk {
            mut ordered,
            visited,
            in_degree,
        } = self.walk();
        if visited == in_degree.len() {
            return ordered;
        }

        for node in in_degree.keys() {
            if !ordered.contains(node) {
                ordered.push(node.clone());
            }
        }
        ordered
    }

    fn walk(self) -> TopologyWalk {
        let mut queue = self
            .in_degree
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(node, _)| node.clone())
            .collect::<VecDeque<_>>();
        let mut ordered = Vec::with_capacity(self.in_degree.len());
        let mut in_degree = self.in_degree;
        let mut visited = 0usize;

        while let Some(node) = queue.pop_front() {
            ordered.push(node.clone());
            visited += 1;
            if let Some(consumers) = self.edges.get(&node) {
                for consumer in consumers {
                    let count = in_degree.get_mut(consumer).expect("consumer must exist");
                    *count -= 1;
                    if *count == 0 {
                        queue.push_back(consumer.clone());
                    }
                }
            }
        }

        TopologyWalk {
            ordered,
            visited,
            in_degree,
        }
    }
}

pub(super) fn topological_order(
    scenarios: &[StoredScenario],
    dependencies: &[StoredDependency],
) -> Vec<String> {
    let mut graph = ScenarioGraph::new(scenarios.iter().map(|scenario| scenario.id.clone()));
    for dependency in dependencies {
        let Some(provider) = dependency.provider_scenario_id.as_ref() else {
            continue;
        };
        graph.add_edge(provider.clone(), dependency.consumer_scenario_id.clone());
    }
    graph.ordered()
}

#[derive(Debug)]
struct TopologyWalk {
    ordered: Vec<String>,
    visited: usize,
    in_degree: BTreeMap<String, usize>,
}
