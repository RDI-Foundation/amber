use std::collections::{BTreeMap, BTreeSet, VecDeque};

use amber_json5 as json5;
use amber_manifest::{CapabilityKind, NetworkProtocol, SlotDecl};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, ProvideRef, Scenario, ScenarioExport,
    ScenarioIr, SlotRef, graph,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use thiserror::Error;

use crate::{
    reporter::{
        CompiledScenario, DirectReporter, DockerComposeReporter, Reporter as _,
        kubernetes::KubernetesReporter, vm::VmReporter,
    },
    targets::{
        mesh::plan::{MeshOptions, ResolvedComponentBinding, build_mesh_plan},
        program_config::build_endpoint_plan,
        storage::build_storage_plan,
    },
};

pub const RUN_PLAN_SCHEMA: &str = "amber.run.plan";
pub const RUN_PLAN_VERSION: u32 = 1;
pub const PLACEMENT_SCHEMA: &str = "amber.run.placement";
pub const PLACEMENT_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunPlan {
    pub schema: String,
    pub version: u32,
    pub mesh_scope: String,
    pub assignments: BTreeMap<String, String>,
    pub sites: BTreeMap<String, RunSitePlan>,
    pub links: Vec<RunLink>,
    pub startup_waves: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunSitePlan {
    pub site: SiteDefinition,
    pub router_identity_id: String,
    pub assigned_components: Vec<String>,
    pub scenario_ir: ScenarioIr,
    pub artifact_files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunLink {
    pub provider_site: String,
    pub consumer_site: String,
    pub provider_component: String,
    pub provide: String,
    pub consumer_component: String,
    pub slot: String,
    pub protocol: NetworkProtocol,
    pub export_name: String,
    pub external_slot_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementFile {
    pub schema: String,
    pub version: u32,
    #[serde(default)]
    pub sites: BTreeMap<String, SiteDefinition>,
    #[serde(default)]
    pub defaults: PlacementDefaults,
    #[serde(default)]
    pub components: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementDefaults {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub vm: Option<String>,
    #[serde(default)]
    pub image: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteDefinition {
    pub kind: SiteKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteKind {
    Direct,
    Vm,
    Compose,
    Kubernetes,
}

#[derive(Debug, Error)]
pub enum PlacementParseError {
    #[error("invalid placement file: {0}")]
    Invalid(String),
    #[error("unsupported placement schema `{actual}`; expected `{expected}`")]
    SchemaMismatch {
        expected: &'static str,
        actual: String,
    },
    #[error("unsupported placement version {actual}; expected {expected}")]
    VersionMismatch { expected: u32, actual: u32 },
}

#[derive(Debug, Error)]
pub enum RunPlanError {
    #[error(transparent)]
    Placement(#[from] PlacementParseError),

    #[error("run planning failed: {0}")]
    Other(String),

    #[error("missing placement site `{site_id}`")]
    UnknownSite { site_id: String },

    #[error("missing placement default for {program_kind}")]
    MissingDefault { program_kind: &'static str },

    #[error(
        "component `{component}` cannot run on site `{site_id}` because {kind:?} sites only \
         support {supported}"
    )]
    UnsupportedPlacement {
        component: String,
        site_id: String,
        kind: SiteKind,
        supported: &'static str,
    },

    #[error(
        "storage `{storage}` is mounted from multiple sites in one run: {sites:?}; first-version \
         mixed-site execution requires storage consumers to stay on one site"
    )]
    StorageSpansSites { storage: String, sites: Vec<String> },
}

pub fn parse_placement_file(contents: &str) -> Result<PlacementFile, PlacementParseError> {
    let placement: PlacementFile =
        json5::from_str(contents).map_err(|err| PlacementParseError::Invalid(err.to_string()))?;
    if placement.schema != PLACEMENT_SCHEMA {
        return Err(PlacementParseError::SchemaMismatch {
            expected: PLACEMENT_SCHEMA,
            actual: placement.schema,
        });
    }
    if placement.version != PLACEMENT_VERSION {
        return Err(PlacementParseError::VersionMismatch {
            expected: PLACEMENT_VERSION,
            actual: placement.version,
        });
    }
    Ok(placement)
}

pub fn build_run_plan(
    compiled: &CompiledScenario,
    placement: Option<&PlacementFile>,
) -> Result<RunPlan, RunPlanError> {
    let scenario = compiled.scenario();
    let endpoint_plan = build_endpoint_plan(scenario)
        .map_err(|err| RunPlanError::Other(format!("failed to build endpoint plan: {err}")))?;
    let mesh_plan = build_mesh_plan(
        scenario,
        &endpoint_plan,
        MeshOptions {
            backend_label: "run plan",
        },
    )
    .map_err(|err| RunPlanError::Other(format!("failed to build mesh plan: {err}")))?;

    let assignments_by_component = resolve_assignments(scenario, placement)?;
    validate_storage_locality(scenario, &assignments_by_component)?;

    let mesh_scope = scenario_mesh_scope(compiled.scenario_ir())?;
    let links = build_cross_site_links(scenario, &mesh_plan, &assignments_by_component);
    let site_dependencies = build_site_dependencies(&mesh_plan, &assignments_by_component);
    let startup_waves = topo_waves(&site_dependencies);

    let links_by_provider_site =
        links
            .iter()
            .fold(BTreeMap::<String, Vec<RunLink>>::new(), |mut acc, link| {
                acc.entry(link.provider_site.clone())
                    .or_default()
                    .push(link.clone());
                acc
            });
    let links_by_consumer_site =
        links
            .iter()
            .fold(BTreeMap::<String, Vec<RunLink>>::new(), |mut acc, link| {
                acc.entry(link.consumer_site.clone())
                    .or_default()
                    .push(link.clone());
                acc
            });

    let mut sites = BTreeMap::new();
    let mut assignments = BTreeMap::new();
    let site_definitions = placement_site_definitions(placement);

    for (component_id, site_id) in &assignments_by_component {
        assignments.insert(
            graph::component_path(scenario, *component_id),
            site_id.clone(),
        );
    }

    let component_ids_by_site = assignments_by_component.iter().fold(
        BTreeMap::<String, Vec<ComponentId>>::new(),
        |mut acc, (component_id, site_id)| {
            acc.entry(site_id.clone()).or_default().push(*component_id);
            acc
        },
    );

    for (site_id, mut program_components) in component_ids_by_site {
        program_components.sort();
        let site =
            site_definitions
                .get(&site_id)
                .cloned()
                .ok_or_else(|| RunPlanError::UnknownSite {
                    site_id: site_id.clone(),
                })?;
        let site_scenario = build_site_scenario(
            scenario,
            &program_components,
            &links_by_provider_site
                .get(&site_id)
                .cloned()
                .unwrap_or_default(),
            &links_by_consumer_site
                .get(&site_id)
                .cloned()
                .unwrap_or_default(),
            &assignments_by_component,
        )?;
        let scenario_ir = ScenarioIr::from(&site_scenario);
        let site_compiled = compiled
            .derive_from_ir(scenario_ir.clone())
            .map_err(|err| RunPlanError::Other(format!("failed to derive site scenario: {err}")))?;
        let artifact_files = render_site_artifact_files(
            site.kind,
            &site_compiled,
            &site_router_identity_id(&site_id),
            &mesh_scope,
        )?;
        let assigned_components = program_components
            .iter()
            .map(|component_id| graph::component_path(scenario, *component_id))
            .collect();
        sites.insert(
            site_id.clone(),
            RunSitePlan {
                site,
                router_identity_id: site_router_identity_id(&site_id),
                assigned_components,
                scenario_ir,
                artifact_files,
            },
        );
    }

    Ok(RunPlan {
        schema: RUN_PLAN_SCHEMA.to_string(),
        version: RUN_PLAN_VERSION,
        mesh_scope,
        assignments,
        sites,
        links,
        startup_waves,
    })
}

fn resolve_assignments(
    scenario: &Scenario,
    placement: Option<&PlacementFile>,
) -> Result<BTreeMap<ComponentId, String>, RunPlanError> {
    let site_definitions = placement_site_definitions(placement);
    let defaults = placement
        .map(|placement| placement.defaults.clone())
        .unwrap_or_else(default_placement_defaults);
    let explicit_components = placement
        .map(|placement| placement.components.clone())
        .unwrap_or_default();

    let mut assignments = BTreeMap::new();
    for (component_id, component) in scenario.components_iter() {
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        let component_path = component.moniker.as_str();
        let site_id = explicit_components
            .get(component_path)
            .cloned()
            .or_else(|| match program {
                amber_scenario::Program::Path(_) => defaults.path.clone(),
                amber_scenario::Program::Vm(_) => defaults.vm.clone(),
                amber_scenario::Program::Image(_) => defaults.image.clone(),
                _ => None,
            })
            .ok_or_else(|| match program {
                amber_scenario::Program::Path(_) => RunPlanError::MissingDefault {
                    program_kind: "program.path",
                },
                amber_scenario::Program::Vm(_) => RunPlanError::MissingDefault {
                    program_kind: "program.vm",
                },
                amber_scenario::Program::Image(_) => RunPlanError::MissingDefault {
                    program_kind: "program.image",
                },
                _ => RunPlanError::Other(format!(
                    "component `{component_path}` uses an unsupported program kind"
                )),
            })?;
        let site = site_definitions
            .get(&site_id)
            .ok_or_else(|| RunPlanError::UnknownSite {
                site_id: site_id.clone(),
            })?;
        validate_program_support(component, &site_id, site.clone())?;
        assignments.insert(component_id, site_id);
    }
    Ok(assignments)
}

fn validate_program_support(
    component: &Component,
    site_id: &str,
    site: SiteDefinition,
) -> Result<(), RunPlanError> {
    let component_path = component.moniker.as_str().to_string();
    let Some(program) = component.program.as_ref() else {
        return Ok(());
    };
    match (site.kind, program) {
        (SiteKind::Direct, amber_scenario::Program::Path(_)) => Ok(()),
        (SiteKind::Vm, amber_scenario::Program::Vm(_)) => Ok(()),
        (SiteKind::Compose, amber_scenario::Program::Image(_))
        | (SiteKind::Kubernetes, amber_scenario::Program::Image(_)) => Ok(()),
        (SiteKind::Direct, _) => Err(RunPlanError::UnsupportedPlacement {
            component: component_path,
            site_id: site_id.to_string(),
            kind: site.kind,
            supported: "program.path workloads",
        }),
        (SiteKind::Vm, _) => Err(RunPlanError::UnsupportedPlacement {
            component: component_path,
            site_id: site_id.to_string(),
            kind: site.kind,
            supported: "program.vm workloads",
        }),
        (SiteKind::Compose, _) | (SiteKind::Kubernetes, _) => {
            Err(RunPlanError::UnsupportedPlacement {
                component: component_path,
                site_id: site_id.to_string(),
                kind: site.kind,
                supported: "program.image workloads",
            })
        }
    }
}

fn validate_storage_locality(
    scenario: &Scenario,
    assignments_by_component: &BTreeMap<ComponentId, String>,
) -> Result<(), RunPlanError> {
    let program_components = assignments_by_component.keys().copied().collect::<Vec<_>>();
    let storage_plan = build_storage_plan(scenario, &program_components);
    let mut sites_by_storage = BTreeMap::<String, BTreeSet<String>>::new();
    for (component_id, mounts) in storage_plan.mounts_by_component {
        let site_id = assignments_by_component
            .get(&component_id)
            .expect("program component assignment should exist");
        for mount in mounts {
            let storage_key = format!(
                "{}::{}",
                mount.identity.owner_moniker, mount.identity.resource
            );
            sites_by_storage
                .entry(storage_key)
                .or_default()
                .insert(site_id.clone());
        }
    }
    for (storage, sites) in sites_by_storage {
        if sites.len() > 1 {
            return Err(RunPlanError::StorageSpansSites {
                storage,
                sites: sites.into_iter().collect(),
            });
        }
    }
    Ok(())
}

fn placement_site_definitions(
    placement: Option<&PlacementFile>,
) -> BTreeMap<String, SiteDefinition> {
    placement
        .map(|placement| placement.sites.clone())
        .unwrap_or_else(default_site_definitions)
}

fn default_site_definitions() -> BTreeMap<String, SiteDefinition> {
    BTreeMap::from([
        (
            "compose_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Compose,
                context: None,
            },
        ),
        (
            "direct_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Direct,
                context: None,
            },
        ),
        (
            "vm_local".to_string(),
            SiteDefinition {
                kind: SiteKind::Vm,
                context: None,
            },
        ),
    ])
}

fn default_placement_defaults() -> PlacementDefaults {
    PlacementDefaults {
        path: Some("direct_local".to_string()),
        vm: Some("vm_local".to_string()),
        image: Some("compose_local".to_string()),
    }
}

fn build_cross_site_links(
    scenario: &Scenario,
    mesh_plan: &crate::targets::mesh::plan::MeshPlan,
    assignments_by_component: &BTreeMap<ComponentId, String>,
) -> Vec<RunLink> {
    let mut links = BTreeMap::<(String, String, String, String, NetworkProtocol), RunLink>::new();

    for binding in mesh_plan.component_bindings() {
        let provider_site = assignments_by_component
            .get(&binding.provider)
            .expect("provider assignment should exist");
        let consumer_site = assignments_by_component
            .get(&binding.consumer)
            .expect("consumer assignment should exist");
        if provider_site == consumer_site {
            continue;
        }

        let export_name = synthetic_export_name(binding);
        let external_slot_name = synthetic_external_slot_name(binding, consumer_site);
        let key = (
            provider_site.clone(),
            consumer_site.clone(),
            export_name.clone(),
            external_slot_name.clone(),
            binding.endpoint.protocol,
        );
        links.entry(key).or_insert_with(|| RunLink {
            provider_site: provider_site.clone(),
            consumer_site: consumer_site.clone(),
            provider_component: graph::component_path(scenario, binding.provider),
            provide: binding.provide.clone(),
            consumer_component: graph::component_path(scenario, binding.consumer),
            slot: binding.slot.clone(),
            protocol: binding.endpoint.protocol,
            export_name,
            external_slot_name,
        });
    }

    links.into_values().collect()
}

fn build_site_dependencies(
    mesh_plan: &crate::targets::mesh::plan::MeshPlan,
    assignments_by_component: &BTreeMap<ComponentId, String>,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut site_dependencies = BTreeMap::<String, BTreeSet<String>>::new();
    for (component_id, site_id) in assignments_by_component {
        site_dependencies.entry(site_id.clone()).or_default();
        if let Some(deps) = mesh_plan.strong_deps().get(component_id) {
            for dep in deps {
                let dep_site = assignments_by_component
                    .get(dep)
                    .expect("dependency assignment should exist");
                if dep_site != site_id {
                    site_dependencies
                        .entry(site_id.clone())
                        .or_default()
                        .insert(dep_site.clone());
                }
            }
        }
    }
    site_dependencies
}

fn topo_waves(site_dependencies: &BTreeMap<String, BTreeSet<String>>) -> Vec<Vec<String>> {
    let mut indegree = BTreeMap::<String, usize>::new();
    let mut outgoing = BTreeMap::<String, BTreeSet<String>>::new();

    for (site, deps) in site_dependencies {
        indegree.entry(site.clone()).or_insert(0);
        for dep in deps {
            outgoing
                .entry(dep.clone())
                .or_default()
                .insert(site.clone());
            *indegree.entry(site.clone()).or_insert(0) += 1;
            indegree.entry(dep.clone()).or_insert(0);
        }
    }

    let mut ready = indegree
        .iter()
        .filter_map(|(site, degree)| (*degree == 0).then_some(site.clone()))
        .collect::<VecDeque<_>>();
    let mut waves = Vec::new();
    while !ready.is_empty() {
        let mut wave = Vec::new();
        let count = ready.len();
        for _ in 0..count {
            let site = ready
                .pop_front()
                .expect("ready queue length should stay consistent");
            wave.push(site.clone());
            if let Some(children) = outgoing.get(&site) {
                for child in children {
                    let degree = indegree
                        .get_mut(child)
                        .expect("child indegree should exist");
                    *degree -= 1;
                    if *degree == 0 {
                        ready.push_back(child.clone());
                    }
                }
            }
        }
        wave.sort();
        waves.push(wave);
    }
    waves
}

fn build_site_scenario(
    scenario: &Scenario,
    program_components: &[ComponentId],
    provided_links: &[RunLink],
    consumed_links: &[RunLink],
    assignments_by_component: &BTreeMap<ComponentId, String>,
) -> Result<Scenario, RunPlanError> {
    let included_components = collect_site_components(scenario, program_components);
    let included_set = included_components.iter().copied().collect::<BTreeSet<_>>();
    let root_id = scenario.root;

    let mut components = vec![None; scenario.components.len()];
    let synthetic_slots = synthetic_root_slots(scenario, consumed_links);

    for component_id in included_components {
        let mut component = scenario.component(component_id).clone();
        component
            .children
            .retain(|child| included_set.contains(child));
        if component.id == root_id {
            component.slots.retain(|name, _| {
                scenario.bindings.iter().any(|binding| {
                    matches!(&binding.from, BindingFrom::External(slot) if slot.component == root_id && slot.name == *name)
                        && included_set.contains(&binding.to.component)
                })
            });
            component.slots.extend(synthetic_slots.clone());
        }
        components[component_id.0] = Some(component);
    }

    let consumer_link_by_slot = consumed_links.iter().fold(
        BTreeMap::<(String, String), RunLink>::new(),
        |mut acc, link| {
            acc.insert(
                (link.consumer_component.clone(), link.slot.clone()),
                link.clone(),
            );
            acc
        },
    );

    let mut bindings = Vec::new();
    for binding in &scenario.bindings {
        if !included_set.contains(&binding.to.component) {
            continue;
        }
        let Some(slot_decl) = scenario
            .component(binding.to.component)
            .slots
            .get(binding.to.name.as_str())
        else {
            continue;
        };
        if slot_decl.decl.kind == CapabilityKind::Storage {
            bindings.push(binding.clone());
            continue;
        }
        match &binding.from {
            BindingFrom::Component(provide) => {
                let provider_site = assignments_by_component
                    .get(&provide.component)
                    .expect("provider site should exist");
                let consumer_site = assignments_by_component
                    .get(&binding.to.component)
                    .expect("consumer site should exist");
                if provider_site == consumer_site {
                    bindings.push(binding.clone());
                    continue;
                }
                let component_path = graph::component_path(scenario, binding.to.component);
                let link = consumer_link_by_slot
                    .get(&(component_path, binding.to.name.clone()))
                    .expect("consumer link should exist");
                bindings.push(BindingEdge {
                    from: BindingFrom::External(SlotRef {
                        component: root_id,
                        name: link.external_slot_name.clone(),
                    }),
                    to: binding.to.clone(),
                    weak: true,
                });
            }
            BindingFrom::External(slot) => {
                if included_set.contains(&slot.component) {
                    bindings.push(binding.clone());
                }
            }
            BindingFrom::Framework(_) | BindingFrom::Resource(_) => bindings.push(binding.clone()),
        }
    }

    let mut exports = scenario
        .exports
        .iter()
        .filter(|export| {
            included_set.contains(&export.from.component)
                && assignments_by_component
                    .get(&export.from.component)
                    .is_some_and(|site_id| {
                        program_components
                            .first()
                            .and_then(|component_id| assignments_by_component.get(component_id))
                            == Some(site_id)
                    })
        })
        .cloned()
        .collect::<Vec<_>>();

    let mut exported_names = exports
        .iter()
        .map(|export| export.name.clone())
        .collect::<BTreeSet<_>>();
    for link in provided_links {
        if !exported_names.insert(link.export_name.clone()) {
            continue;
        }
        let provider_component = scenario
            .components_iter()
            .find_map(|(component_id, component)| {
                (component.moniker.as_str() == link.provider_component)
                    .then_some((component_id, component))
            })
            .expect("provider component should exist");
        let provide_decl = provider_component
            .1
            .provides
            .get(link.provide.as_str())
            .expect("provider provide should exist");
        exports.push(ScenarioExport {
            name: link.export_name.clone(),
            capability: provide_decl.decl.clone(),
            from: ProvideRef {
                component: provider_component.0,
                name: link.provide.clone(),
            },
        });
    }

    let mut site_scenario = Scenario {
        root: root_id,
        components,
        bindings,
        exports,
    };
    site_scenario.normalize_order();
    Ok(site_scenario)
}

fn collect_site_components(
    scenario: &Scenario,
    program_components: &[ComponentId],
) -> Vec<ComponentId> {
    let mut included = BTreeSet::new();
    included.insert(scenario.root);

    for component_id in program_components {
        let mut current = Some(*component_id);
        while let Some(component_id) = current {
            if !included.insert(component_id) {
                break;
            }
            current = scenario.component(component_id).parent;
        }
    }

    for binding in &scenario.bindings {
        let Some(slot_decl) = scenario
            .component(binding.to.component)
            .slots
            .get(binding.to.name.as_str())
        else {
            continue;
        };
        if slot_decl.decl.kind != CapabilityKind::Storage
            || !program_components.contains(&binding.to.component)
        {
            continue;
        }
        let BindingFrom::Resource(resource) = &binding.from else {
            continue;
        };
        let mut current = Some(resource.component);
        while let Some(component_id) = current {
            if !included.insert(component_id) {
                break;
            }
            current = scenario.component(component_id).parent;
        }
    }

    included.into_iter().collect()
}

fn synthetic_root_slots(
    scenario: &Scenario,
    consumed_links: &[RunLink],
) -> BTreeMap<String, SlotDecl> {
    let mut slots = BTreeMap::new();
    for link in consumed_links {
        let provider_component = scenario
            .components_iter()
            .find_map(|(_, component)| {
                (component.moniker.as_str() == link.provider_component).then_some(component)
            })
            .expect("provider component should exist");
        let provide_decl = provider_component
            .provides
            .get(link.provide.as_str())
            .expect("provider provide should exist");
        slots.insert(
            link.external_slot_name.clone(),
            SlotDecl::builder()
                .decl(provide_decl.decl.clone())
                .optional(false)
                .multiple(false)
                .build(),
        );
    }
    slots
}

fn synthetic_export_name(binding: &ResolvedComponentBinding) -> String {
    synthetic_name(
        "amber_export",
        &[
            binding.provider.0.to_string(),
            binding.provide.clone(),
            binding.endpoint.protocol.to_string(),
        ],
    )
}

fn synthetic_external_slot_name(binding: &ResolvedComponentBinding, consumer_site: &str) -> String {
    synthetic_name(
        "amber_link",
        &[
            consumer_site.to_string(),
            binding.provider.0.to_string(),
            binding.provide.clone(),
            binding.endpoint.protocol.to_string(),
        ],
    )
}

fn synthetic_name(prefix: &str, parts: &[String]) -> String {
    let mut hasher = sha2::Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let suffix: String = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("{prefix}_{suffix}")
}

fn scenario_mesh_scope(scenario_ir: &ScenarioIr) -> Result<String, RunPlanError> {
    let bytes = serde_json::to_vec(scenario_ir)
        .map_err(|err| RunPlanError::Other(format!("failed to serialize scenario IR: {err}")))?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    Ok(format!(
        "sha256:{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    ))
}

fn site_router_identity_id(site_id: &str) -> String {
    format!("/site/{site_id}/router")
}

fn render_site_artifact_files(
    site_kind: SiteKind,
    compiled: &CompiledScenario,
    router_identity_id: &str,
    mesh_scope: &str,
) -> Result<BTreeMap<String, String>, RunPlanError> {
    let mut files = match site_kind {
        SiteKind::Direct => {
            DirectReporter
                .emit(compiled)
                .map_err(|err| RunPlanError::Other(format!("failed to render direct site: {err}")))?
                .files
        }
        SiteKind::Vm => {
            VmReporter
                .emit(compiled)
                .map_err(|err| RunPlanError::Other(format!("failed to render vm site: {err}")))?
                .files
        }
        SiteKind::Compose => {
            DockerComposeReporter
                .emit(compiled)
                .map_err(|err| {
                    RunPlanError::Other(format!("failed to render compose site: {err}"))
                })?
                .files
        }
        SiteKind::Kubernetes => {
            KubernetesReporter
                .emit(compiled)
                .map_err(|err| {
                    RunPlanError::Other(format!("failed to render kubernetes site: {err}"))
                })?
                .files
        }
    };
    rewrite_router_identity(site_kind, &mut files, router_identity_id);
    rewrite_mesh_scope(
        &mut files,
        &scenario_mesh_scope(compiled.scenario_ir())?,
        mesh_scope,
    );
    Ok(files
        .into_iter()
        .map(|(path, contents)| (path.to_string_lossy().into_owned(), contents))
        .collect())
}

fn rewrite_router_identity(
    site_kind: SiteKind,
    files: &mut BTreeMap<std::path::PathBuf, String>,
    router_identity_id: &str,
) {
    let existing_router_id = match site_kind {
        SiteKind::Direct => crate::targets::direct::ROUTER_IDENTITY_ID,
        SiteKind::Vm => crate::targets::vm::ROUTER_IDENTITY_ID,
        SiteKind::Compose | SiteKind::Kubernetes => {
            crate::targets::mesh::mesh_config::DEFAULT_ROUTER_ID
        }
    };
    if existing_router_id == router_identity_id {
        return;
    }
    for contents in files.values_mut() {
        *contents = contents.replace(existing_router_id, router_identity_id);
    }
}

fn rewrite_mesh_scope(
    files: &mut BTreeMap<std::path::PathBuf, String>,
    existing_mesh_scope: &str,
    mesh_scope: &str,
) {
    if existing_mesh_scope == mesh_scope {
        return;
    }
    for contents in files.values_mut() {
        *contents = contents.replace(existing_mesh_scope, mesh_scope);
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, path::Path};

    use amber_manifest::ManifestRef;
    use amber_resolver::Resolver;
    use tempfile::TempDir;
    use url::Url;

    use super::*;
    use crate::{CompileOptions, Compiler, DigestStore, ResolverRegistry};

    fn tmp_dir(prefix: &str) -> TempDir {
        tempfile::Builder::new().prefix(prefix).tempdir().unwrap()
    }

    fn write(path: &Path, contents: &str) {
        fs::write(path, contents).unwrap();
    }

    fn manifest_ref(path: &Path) -> ManifestRef {
        ManifestRef::from_url(Url::from_file_path(path).unwrap())
    }

    fn image_server_manifest() -> &'static str {
        r#"{
  manifest_version: "0.3.0",
  program: {
    image: "busybox:1.36.1",
    entrypoint: ["sh", "-c", "sleep 30"],
    network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
  },
  provides: { api: { kind: "http", endpoint: "http" } },
  exports: { api: "api" }
}"#
    }

    fn path_server_manifest() -> &'static str {
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: ["sh", "-c", "sleep 30"],
    network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
  },
  provides: { api: { kind: "http", endpoint: "http" } },
  exports: { api: "api" }
}"#
    }

    fn vm_server_manifest() -> &'static str {
        r##"{
  manifest_version: "0.3.0",
  program: {
    vm: {
      image: "ubuntu.img",
      cpus: 1,
      memory_mib: 512,
      network: {
        endpoints: [{ name: "http", port: 8080, protocol: "http" }],
        egress: "none"
      },
      cloud_init: {
        user_data: "#cloud-config\nruncmd:\n  - [sh, -lc, 'sleep infinity']\n"
      }
    }
  },
  provides: { api: { kind: "http", endpoint: "http" } },
  exports: { api: "api" }
}"##
    }

    fn startup_b_manifest() -> &'static str {
        r#"{
  manifest_version: "0.3.0",
  slots: {
    from_c: { kind: "http" },
    from_d: { kind: "http" }
  },
  program: {
    image: "busybox:1.36.1",
    entrypoint: ["sh", "-c", "sleep 30"],
    env: {
      FROM_C_URL: "${slots.from_c.url}",
      FROM_D_URL: "${slots.from_d.url}"
    },
    network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
  },
  provides: { api: { kind: "http", endpoint: "http" } },
  exports: { api: "api" }
}"#
    }

    fn startup_a_manifest() -> &'static str {
        r#"{
  manifest_version: "0.3.0",
  slots: {
    from_b: { kind: "http" },
    from_c: { kind: "http" }
  },
  program: {
    path: "/usr/bin/env",
    args: ["sh", "-c", "sleep 30"],
    env: {
      FROM_B_URL: "${slots.from_b.url}",
      FROM_C_URL: "${slots.from_c.url}"
    },
    network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
  },
  provides: { api: { kind: "http", endpoint: "http" } },
  exports: { api: "api" }
}"#
    }

    fn startup_d_manifest() -> &'static str {
        r##"{
  manifest_version: "0.3.0",
  slots: { from_e: { kind: "http" } },
  program: {
    vm: {
      image: "ubuntu.img",
      cpus: 1,
      memory_mib: 512,
      network: {
        endpoints: [{ name: "http", port: 8080, protocol: "http" }],
        egress: "none"
      },
      cloud_init: {
        user_data: "#cloud-config\nwrite_files:\n  - path: /etc/from-e-url\n    content: '${slots.from_e.url}'\nruncmd:\n  - [sh, -lc, 'sleep infinity']\n"
      }
    }
  },
  provides: { api: { kind: "http", endpoint: "http" } },
  exports: { api: "api" }
}"##
    }

    fn startup_c_manifest() -> &'static str {
        r#"{
  manifest_version: "0.3.0",
  slots: { from_d: { kind: "http" } },
  program: {
    image: "busybox:1.36.1",
    entrypoint: ["sh", "-c", "sleep 30"],
    env: { FROM_D_URL: "${slots.from_d.url}" },
    network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
  },
  provides: { api: { kind: "http", endpoint: "http" } },
  exports: { api: "api" }
}"#
    }

    fn startup_e_manifest() -> &'static str {
        r#"{
  manifest_version: "0.3.0",
  program: {
    image: "busybox:1.36.1",
    entrypoint: ["sh", "-c", "sleep 30"],
    network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
  },
  provides: { api: { kind: "http", endpoint: "http" } },
  exports: { api: "api" }
}"#
    }

    fn storage_consumer_manifest() -> &'static str {
        r#"{
  manifest_version: "0.3.0",
  slots: { state: { kind: "storage" } },
  program: {
    image: "busybox:1.36.1",
    entrypoint: ["sh", "-c", "sleep 30"],
    network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] },
    mounts: [{ from: "slots.state", path: "/data" }]
  },
  provides: { api: { kind: "http", endpoint: "http" } },
  exports: { api: "api" }
}"#
    }

    async fn compile(root: &Path) -> CompiledScenario {
        let compiler = Compiler::new(Resolver::new(), DigestStore::default())
            .with_registry(ResolverRegistry::default());
        let output = compiler
            .compile(
                manifest_ref(root),
                CompileOptions {
                    resolve: Default::default(),
                    optimize: Default::default(),
                },
            )
            .await
            .expect("scenario should compile");
        CompiledScenario::from_compile_output(&output).expect("compiled scenario")
    }

    #[tokio::test]
    async fn default_placement_prefers_compose_for_images() {
        let dir = tmp_dir("run-plan-default-placement-");
        let path_child = dir.path().join("tool.json5");
        let vm_child = dir.path().join("vm.json5");
        let image_child = dir.path().join("image.json5");
        let root = dir.path().join("root.json5");

        write(&path_child, path_server_manifest());
        write(&vm_child, vm_server_manifest());
        write(&image_child, image_server_manifest());
        write(
            &root,
            r##"{
  manifest_version: "0.3.0",
  components: {
    tool: "./tool.json5",
    vm: "./vm.json5",
    image: "./image.json5"
  },
  exports: {
    tool_api: "#tool.api",
    vm_api: "#vm.api",
    image_api: "#image.api"
  }
}"##,
        );

        let compiled = compile(&root).await;
        let plan = build_run_plan(&compiled, None).expect("run plan should build");
        assert_eq!(plan.assignments["/tool"], "direct_local");
        assert_eq!(plan.assignments["/vm"], "vm_local");
        assert_eq!(plan.assignments["/image"], "compose_local");
    }

    #[tokio::test]
    async fn placement_file_can_force_kubernetes() {
        let dir = tmp_dir("run-plan-placement-file-");
        let image_child = dir.path().join("image.json5");
        let root = dir.path().join("root.json5");

        write(&image_child, image_server_manifest());
        write(
            &root,
            r##"{
  manifest_version: "0.3.0",
  components: { image: "./image.json5" },
  exports: { image_api: "#image.api" }
}"##,
        );

        let compiled = compile(&root).await;
        let placement = parse_placement_file(
            r#"{
  schema: "amber.run.placement",
  version: 1,
  sites: {
    kind_local: { kind: "kubernetes", context: "kind-amber" }
  },
  defaults: {
    image: "kind_local"
  }
}"#,
        )
        .expect("placement should parse");
        let plan = build_run_plan(&compiled, Some(&placement)).expect("run plan should build");
        assert_eq!(plan.assignments["/image"], "kind_local");
        assert_eq!(plan.sites["kind_local"].site.kind, SiteKind::Kubernetes);
        assert_eq!(
            plan.sites["kind_local"].site.context.as_deref(),
            Some("kind-amber")
        );
    }

    #[tokio::test]
    async fn storage_locality_rejects_cross_site_consumers() {
        let dir = tmp_dir("run-plan-storage-locality-");
        let consumer = dir.path().join("consumer.json5");
        let root = dir.path().join("root.json5");

        write(&consumer, storage_consumer_manifest());
        write(
            &root,
            r##"{
  manifest_version: "0.3.0",
  resources: {
    state: { kind: "storage" }
  },
  components: {
    a: "./consumer.json5"
  },
  bindings: [
    { from: "resources.state", to: "#a.state" }
  ],
  exports: {
    a_api: "#a.api"
  }
}"##,
        );

        let compiled = compile(&root).await;
        let mut scenario = compiled.scenario().clone();
        let a_id = scenario
            .components_iter()
            .find_map(|(component_id, component)| {
                (component.moniker.as_str() == "/a").then_some(component_id)
            })
            .expect("component /a should exist");
        let b_id = amber_scenario::ComponentId(scenario.components.len());
        let mut b_component = scenario.component(a_id).clone();
        b_component.id = b_id;
        b_component.moniker = "/b".to_string().into();
        b_component.parent = Some(scenario.root);
        scenario.component_mut(scenario.root).children.push(b_id);
        scenario.components.push(Some(b_component));
        scenario.bindings.push(BindingEdge {
            from: BindingFrom::Resource(amber_scenario::ResourceRef {
                component: scenario.root,
                name: "state".to_string(),
            }),
            to: SlotRef {
                component: b_id,
                name: "state".to_string(),
            },
            weak: false,
        });

        let assignments = BTreeMap::from([
            (a_id, "compose_a".to_string()),
            (b_id, "compose_b".to_string()),
        ]);
        let err = validate_storage_locality(&scenario, &assignments)
            .expect_err("storage locality should fail");
        assert!(matches!(
            err,
            RunPlanError::StorageSpansSites { ref storage, ref sites }
                if storage.contains("state")
                    && sites == &vec!["compose_a".to_string(), "compose_b".to_string()]
        ));
    }

    #[tokio::test]
    async fn startup_waves_follow_cross_site_dependencies() {
        let dir = tmp_dir("run-plan-startup-waves-");
        let a_node = dir.path().join("a.json5");
        let b_node = dir.path().join("b.json5");
        let c_node = dir.path().join("c.json5");
        let d_node = dir.path().join("d.json5");
        let e_node = dir.path().join("e.json5");
        let root = dir.path().join("root.json5");
        write(&a_node, startup_a_manifest());
        write(&b_node, startup_b_manifest());
        write(&c_node, startup_c_manifest());
        write(&d_node, startup_d_manifest());
        write(&e_node, startup_e_manifest());
        write(
            &root,
            r##"{
  manifest_version: "0.3.0",
  components: {
    a: "./a.json5",
    b: "./b.json5",
    c: "./c.json5",
    d: "./d.json5",
    e: "./e.json5"
  },
  bindings: [
    { from: "#b.api", to: "#a.from_b" },
    { from: "#c.api", to: "#a.from_c" },
    { from: "#c.api", to: "#b.from_c" },
    { from: "#d.api", to: "#b.from_d" },
    { from: "#d.api", to: "#c.from_d" },
    { from: "#e.api", to: "#d.from_e" }
  ],
  exports: {
    a_api: "#a.api",
    b_api: "#b.api",
    c_api: "#c.api",
    d_api: "#d.api",
    e_api: "#e.api"
  }
}"##,
        );

        let compiled = compile(&root).await;
        let placement = parse_placement_file(
            r#"{
  schema: "amber.run.placement",
  version: 1,
  sites: {
    direct_local: { kind: "direct" },
    compose_b: { kind: "compose" },
    kind_c: { kind: "kubernetes", context: "kind-amber" },
    vm_d: { kind: "vm" },
    compose_e: { kind: "compose" }
  },
  components: {
    "/a": "direct_local",
    "/b": "compose_b",
    "/c": "kind_c",
    "/d": "vm_d",
    "/e": "compose_e"
  }
}"#,
        )
        .expect("placement should parse");

        let plan = build_run_plan(&compiled, Some(&placement)).expect("run plan should build");
        let order = plan
            .startup_waves
            .iter()
            .flat_map(|wave| wave.iter().cloned())
            .collect::<Vec<_>>();
        assert_eq!(
            order,
            vec![
                "compose_e".to_string(),
                "vm_d".to_string(),
                "kind_c".to_string(),
                "compose_b".to_string(),
                "direct_local".to_string()
            ]
        );
        assert_eq!(plan.links.len(), 6);
    }

    #[tokio::test]
    async fn site_artifacts_use_global_mesh_scope() {
        let dir = tmp_dir("run-plan-global-mesh-scope-");
        let path_child = dir.path().join("tool.json5");
        let image_child = dir.path().join("image.json5");
        let root = dir.path().join("root.json5");

        write(&path_child, path_server_manifest());
        write(&image_child, image_server_manifest());
        write(
            &root,
            r##"{
  manifest_version: "0.3.0",
  components: {
    tool: "./tool.json5",
    image: "./image.json5"
  },
  exports: {
    tool_api: "#tool.api",
    image_api: "#image.api"
  }
}"##,
        );

        let compiled = compile(&root).await;
        let plan = build_run_plan(&compiled, None).expect("run plan should build");

        for site_id in ["direct_local", "compose_local"] {
            let site = plan.sites.get(site_id).expect("site should exist");
            let site_mesh_scope =
                scenario_mesh_scope(&site.scenario_ir).expect("site scope should compute");
            assert_ne!(site_mesh_scope, plan.mesh_scope);

            let artifact = site
                .artifact_files
                .values()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                artifact.contains(&plan.mesh_scope),
                "site artifact for {site_id} should contain the global mesh scope"
            );
            assert!(
                !artifact.contains(&site_mesh_scope),
                "site artifact for {site_id} should not retain its site-local mesh scope"
            );
        }
    }
}
