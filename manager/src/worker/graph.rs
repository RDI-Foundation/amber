use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::store::{StoredDependency, StoredScenario};

pub(super) fn topological_order(
    scenarios: &[StoredScenario],
    dependencies: &[StoredDependency],
) -> Vec<String> {
    let mut edges = BTreeMap::<String, BTreeSet<String>>::new();
    let mut in_degree = scenarios
        .iter()
        .map(|scenario| (scenario.id.clone(), 0usize))
        .collect::<BTreeMap<_, _>>();

    for dependency in dependencies {
        let Some(provider) = dependency.provider_scenario_id.as_ref() else {
            continue;
        };
        if add_edge(
            &mut edges,
            &mut in_degree,
            provider.clone(),
            dependency.consumer_scenario_id.clone(),
        ) {
            continue;
        }
    }

    let mut queue = in_degree
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(node, _)| node.clone())
        .collect::<VecDeque<_>>();
    let mut ordered = Vec::with_capacity(in_degree.len());

    while let Some(node) = queue.pop_front() {
        ordered.push(node.clone());
        if let Some(consumers) = edges.get(&node) {
            for consumer in consumers {
                let count = in_degree.get_mut(consumer).expect("consumer must exist");
                *count -= 1;
                if *count == 0 {
                    queue.push_back(consumer.clone());
                }
            }
        }
    }

    if ordered.len() == in_degree.len() {
        return ordered;
    }

    for scenario in in_degree.keys() {
        if !ordered.contains(scenario) {
            ordered.push(scenario.clone());
        }
    }
    ordered
}

pub(super) fn add_edge(
    edges: &mut BTreeMap<String, BTreeSet<String>>,
    in_degree: &mut BTreeMap<String, usize>,
    provider: String,
    consumer: String,
) -> bool {
    in_degree.entry(provider.clone()).or_insert(0);
    in_degree.entry(consumer.clone()).or_insert(0);
    let inserted = edges.entry(provider).or_default().insert(consumer.clone());
    if inserted {
        *in_degree.get_mut(&consumer).expect("consumer should exist") += 1;
    }
    inserted
}
