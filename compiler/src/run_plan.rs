use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::PathBuf,
};

use amber_json5 as json5;
use amber_manifest::{
    BindingSource as ManifestBindingSource, BindingTarget as ManifestBindingTarget, CapabilityKind,
    ChildTemplateAllowedManifests, ChildTemplateDecl, ComponentDecl, Manifest, ManifestRef,
    MountSource, NetworkProtocol, Program as ManifestProgram, RuntimeBackend, SlotDecl,
};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, ProvideRef, Scenario, ScenarioExport,
    ScenarioIr, SlotRef, graph,
};
use base64::Engine as _;
use glob::Pattern;
use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use thiserror::Error;
use url::Url;

use crate::{
    reporter::CompiledScenario,
    targets::{
        mesh::plan::{MeshOptions, ResolvedComponentBinding, build_mesh_plan},
        program_config::build_endpoint_plan,
        storage::build_storage_plan,
    },
};

pub const RUN_PLAN_SCHEMA: &str = "amber.run.plan";
pub const RUN_PLAN_VERSION: u32 = 2;
pub const PLACEMENT_SCHEMA: &str = "amber.run.placement";
pub const PLACEMENT_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunPlan {
    pub schema: String,
    pub version: u32,
    pub mesh_scope: String,
    #[serde(default = "default_base_scenario")]
    pub base_scenario: ScenarioIr,
    #[serde(default)]
    pub offered_sites: BTreeMap<String, SiteDefinition>,
    #[serde(default)]
    pub defaults: PlacementDefaults,
    #[serde(default)]
    pub initial_active_sites: Vec<String>,
    #[serde(default)]
    pub standby_sites: Vec<String>,
    #[serde(default)]
    pub dynamic_enabled_sites: Vec<String>,
    #[serde(default)]
    pub control_only_sites: Vec<String>,
    #[serde(default)]
    pub active_site_capabilities: BTreeMap<String, ActiveSiteCapabilities>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub placement_components: BTreeMap<String, String>,
    pub assignments: BTreeMap<String, String>,
    pub sites: BTreeMap<String, RunSitePlan>,
    pub links: Vec<RunLink>,
    pub startup_waves: Vec<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunPlanActivationState {
    pub standby_sites: Vec<String>,
    pub initial_active_sites: Vec<String>,
    pub dynamic_enabled_sites: Vec<String>,
    pub control_only_sites: Vec<String>,
    pub active_site_capabilities: BTreeMap<String, ActiveSiteCapabilities>,
}

fn default_base_scenario() -> ScenarioIr {
    ScenarioIr {
        schema: amber_scenario::SCENARIO_IR_SCHEMA.to_string(),
        version: amber_scenario::SCENARIO_IR_VERSION,
        root: 0,
        components: Vec::new(),
        bindings: Vec::new(),
        exports: Vec::new(),
        manifest_catalog: BTreeMap::new(),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveSiteCapabilities {
    pub cross_site_routing: bool,
    pub dynamic_workloads: bool,
    pub privileged_control: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RunSitePlan {
    pub site: SiteDefinition,
    pub router_identity_id: String,
    pub assigned_components: Vec<String>,
    pub scenario_ir: ScenarioIr,
    pub artifact_files: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnmanagedExport {
    pub site_id: String,
    pub kind: SiteKind,
    pub files: BTreeMap<PathBuf, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunLink {
    pub provider_site: String,
    pub consumer_site: String,
    pub provider_component: String,
    pub provide: String,
    pub consumer_component: String,
    pub slot: String,
    pub weak: bool,
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

    #[error("cyclic strong cross-site dependencies prevent startup ordering for sites {sites:?}")]
    CyclicSiteDependencies { sites: Vec<String> },
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error(
    "unmanaged {requested} export currently requires a single {requested} site, but the resolved \
     run plan contains {sites}"
)]
pub struct UnmanagedExportError {
    requested: &'static str,
    sites: String,
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
    build_run_plan_with_activation(compiled, placement, None)
}

pub fn build_run_plan_with_activation(
    compiled: &CompiledScenario,
    placement: Option<&PlacementFile>,
    activation_override: Option<&RunPlanActivationState>,
) -> Result<RunPlan, RunPlanError> {
    let scenario = compiled.scenario();
    let offered_sites = placement_site_definitions(placement);
    let defaults = placement
        .map(|placement| placement.defaults.clone())
        .unwrap_or_else(default_placement_defaults);
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

    let placement_components = placement_component_overrides(placement);
    let assignments_by_component = resolve_assignments(
        scenario,
        &offered_sites,
        &defaults,
        placement_components.clone(),
    )?;
    validate_storage_locality(scenario, &assignments_by_component)?;

    let (
        standby_sites,
        initial_active_sites,
        dynamic_enabled_sites,
        control_only_sites,
        active_site_capabilities,
    ) = if let Some(activation) = activation_override {
        validate_activation_override(&offered_sites, activation)?;
        (
            activation.standby_sites.clone(),
            activation.initial_active_sites.clone(),
            activation.dynamic_enabled_sites.clone(),
            activation.control_only_sites.clone(),
            activation.active_site_capabilities.clone(),
        )
    } else {
        let standby_sites = analyze_standby_sites(scenario, &offered_sites, &defaults)?
            .into_iter()
            .collect::<Vec<_>>();
        let static_active_sites = assignments_by_component
            .values()
            .cloned()
            .collect::<BTreeSet<_>>();
        let standby_site_set = standby_sites.iter().cloned().collect::<BTreeSet<_>>();
        let control_only_sites = Vec::new();
        let control_only_site_set = control_only_sites.iter().cloned().collect::<BTreeSet<_>>();
        let initial_active_sites = static_active_sites
            .union(&standby_site_set)
            .cloned()
            .chain(control_only_site_set.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let dynamic_enabled_sites = initial_active_sites
            .iter()
            .filter(|site_id| !control_only_site_set.contains(*site_id))
            .cloned()
            .collect::<Vec<_>>();
        let active_site_capabilities: BTreeMap<String, ActiveSiteCapabilities> =
            initial_active_sites
                .iter()
                .map(|site_id| {
                    (
                        site_id.clone(),
                        ActiveSiteCapabilities {
                            cross_site_routing: true,
                            dynamic_workloads: dynamic_enabled_sites.contains(site_id),
                            privileged_control: true,
                        },
                    )
                })
                .collect();
        (
            standby_sites,
            initial_active_sites,
            dynamic_enabled_sites,
            control_only_sites,
            active_site_capabilities,
        )
    };
    let initial_active_site_set = initial_active_sites
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let assigned_outside_active = assignments_by_component
        .values()
        .find(|site_id| !initial_active_site_set.contains(site_id.as_str()))
        .cloned();
    if let Some(site_id) = assigned_outside_active {
        return Err(RunPlanError::Other(format!(
            "component placement selected site `{site_id}`, but the frozen activation state does \
             not allow that site to be active"
        )));
    }

    let mesh_scope = scenario_mesh_scope(compiled.scenario_ir())?;
    let links = build_cross_site_links(scenario, &mesh_plan, &assignments_by_component);
    let site_dependencies =
        build_site_dependencies(&mesh_plan, &assignments_by_component, &initial_active_sites);
    let startup_waves = topo_waves(&site_dependencies)?;

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

    for (component_id, site_id) in &assignments_by_component {
        assignments.insert(
            graph::component_path(scenario, *component_id),
            site_id.clone(),
        );
    }

    let mut component_ids_by_site = assignments_by_component.iter().fold(
        BTreeMap::<String, Vec<ComponentId>>::new(),
        |mut acc, (component_id, site_id)| {
            acc.entry(site_id.clone()).or_default().push(*component_id);
            acc
        },
    );

    for site_id in &initial_active_sites {
        let mut program_components = component_ids_by_site.remove(site_id).unwrap_or_default();
        program_components.sort();
        let site =
            offered_sites
                .get(site_id)
                .cloned()
                .ok_or_else(|| RunPlanError::UnknownSite {
                    site_id: site_id.clone(),
                })?;
        let site_scenario = build_site_scenario(
            scenario,
            site_id,
            &program_components,
            &links_by_provider_site
                .get(site_id)
                .cloned()
                .unwrap_or_default(),
            &links_by_consumer_site
                .get(site_id)
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
            &site_router_identity_id(site_id),
            &mesh_scope,
            active_site_capabilities
                .get(site_id)
                .is_some_and(|capabilities| {
                    capabilities.cross_site_routing
                        || capabilities.dynamic_workloads
                        || capabilities.privileged_control
                }),
        )?;
        let assigned_components = program_components
            .iter()
            .map(|component_id| graph::component_path(scenario, *component_id))
            .collect();
        sites.insert(
            site_id.clone(),
            RunSitePlan {
                site,
                router_identity_id: site_router_identity_id(site_id),
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
        base_scenario: compiled.scenario_ir().clone(),
        offered_sites,
        defaults,
        initial_active_sites,
        standby_sites,
        dynamic_enabled_sites,
        control_only_sites,
        active_site_capabilities,
        placement_components,
        assignments,
        sites,
        links,
        startup_waves,
    })
}

fn validate_activation_override(
    offered_sites: &BTreeMap<String, SiteDefinition>,
    activation: &RunPlanActivationState,
) -> Result<(), RunPlanError> {
    for site_id in activation
        .standby_sites
        .iter()
        .chain(&activation.initial_active_sites)
        .chain(&activation.dynamic_enabled_sites)
        .chain(&activation.control_only_sites)
        .chain(activation.active_site_capabilities.keys())
    {
        if !offered_sites.contains_key(site_id) {
            return Err(RunPlanError::UnknownSite {
                site_id: site_id.clone(),
            });
        }
    }
    Ok(())
}

pub fn build_homogeneous_export_run_plan(
    compiled: &CompiledScenario,
    requested_kind: SiteKind,
) -> Result<RunPlan, RunPlanError> {
    let site_id = homogeneous_export_site_id(requested_kind).to_string();
    let placement = PlacementFile {
        schema: PLACEMENT_SCHEMA.to_string(),
        version: PLACEMENT_VERSION,
        sites: BTreeMap::from([(
            site_id.clone(),
            SiteDefinition {
                kind: requested_kind,
                context: None,
            },
        )]),
        defaults: PlacementDefaults {
            path: Some(site_id.clone()),
            vm: Some(site_id.clone()),
            image: Some(site_id),
        },
        components: BTreeMap::new(),
    };
    build_run_plan(compiled, Some(&placement))
}

pub fn build_unmanaged_export(
    run_plan: &RunPlan,
    requested_kind: SiteKind,
) -> Result<UnmanagedExport, UnmanagedExportError> {
    let requested = site_kind_name(requested_kind);
    let resolved_sites = run_plan
        .sites
        .iter()
        .map(|(site_id, site_plan)| {
            format!("`{site_id}` ({})", site_kind_name(site_plan.site.kind))
        })
        .collect::<Vec<_>>();
    if run_plan.sites.len() != 1
        || run_plan
            .sites
            .values()
            .next()
            .is_none_or(|site_plan| site_plan.site.kind != requested_kind)
    {
        return Err(UnmanagedExportError {
            requested,
            sites: if resolved_sites.is_empty() {
                "<no sites>".to_string()
            } else {
                resolved_sites.join(", ")
            },
        });
    }

    let (site_id, site_plan) = run_plan
        .sites
        .iter()
        .next()
        .expect("site count should be one after validation");
    Ok(UnmanagedExport {
        site_id: site_id.clone(),
        kind: site_plan.site.kind,
        files: site_plan
            .artifact_files
            .iter()
            .map(|(path, contents)| (PathBuf::from(path), contents.clone()))
            .collect(),
    })
}

fn resolve_assignments(
    scenario: &Scenario,
    site_definitions: &BTreeMap<String, SiteDefinition>,
    defaults: &PlacementDefaults,
    explicit_components: BTreeMap<String, String>,
) -> Result<BTreeMap<ComponentId, String>, RunPlanError> {
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

fn placement_component_overrides(placement: Option<&PlacementFile>) -> BTreeMap<String, String> {
    placement
        .map(|placement| placement.components.clone())
        .unwrap_or_default()
}

fn site_kind_name(kind: SiteKind) -> &'static str {
    match kind {
        SiteKind::Direct => "direct",
        SiteKind::Vm => "vm",
        SiteKind::Compose => "compose",
        SiteKind::Kubernetes => "kubernetes",
    }
}

fn homogeneous_export_site_id(kind: SiteKind) -> &'static str {
    match kind {
        SiteKind::Direct => "direct_local",
        SiteKind::Vm => "vm_local",
        SiteKind::Compose => "compose_local",
        SiteKind::Kubernetes => "kubernetes_local",
    }
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

#[derive(Clone, Debug)]
struct FrozenChildTemplateSpec {
    manifest: Option<String>,
    allowed_manifests: Option<Vec<String>>,
    possible_backends: Vec<RuntimeBackend>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum StorageIdentityKey {
    ExternalSlot { owner: String, slot: String },
    Resource { owner: String, resource: String },
}

#[derive(Clone, Debug, Default)]
struct FragmentContext {
    storage_slots: BTreeMap<String, StorageIdentityKey>,
}

struct FragmentAnalyzer<'a> {
    catalog: &'a BTreeMap<String, amber_scenario::ManifestCatalogEntry>,
    site_definitions: &'a BTreeMap<String, SiteDefinition>,
    defaults: &'a PlacementDefaults,
    required_sites: BTreeSet<String>,
    storage_sites: BTreeMap<StorageIdentityKey, BTreeSet<String>>,
}

fn analyze_standby_sites(
    scenario: &Scenario,
    site_definitions: &BTreeMap<String, SiteDefinition>,
    defaults: &PlacementDefaults,
) -> Result<BTreeSet<String>, RunPlanError> {
    let mut requested_sites = BTreeSet::new();
    let mut requested_kinds = BTreeSet::new();

    for template in collect_frozen_child_templates(scenario)? {
        match (
            template.manifest.as_deref(),
            template.allowed_manifests.as_ref(),
        ) {
            (Some(key), None) => {
                requested_sites.extend(analyze_manifest_root_sites(
                    &scenario.manifest_catalog,
                    site_definitions,
                    defaults,
                    key,
                )?);
            }
            (None, Some(keys)) if template.possible_backends.is_empty() => {
                for key in keys {
                    requested_sites.extend(analyze_manifest_root_sites(
                        &scenario.manifest_catalog,
                        site_definitions,
                        defaults,
                        key,
                    )?);
                }
            }
            (None, Some(_)) => {
                requested_kinds.extend(
                    template
                        .possible_backends
                        .into_iter()
                        .map(site_kind_for_runtime_backend),
                );
            }
            (Some(_), Some(_)) | (None, None) => {
                unreachable!("scenario IR validation enforces child-template manifest shape")
            }
        }
    }

    for kind in requested_kinds {
        requested_sites.extend(
            site_definitions
                .iter()
                .filter_map(|(site_id, site)| (site.kind == kind).then_some(site_id.clone())),
        );
    }

    Ok(requested_sites)
}

fn collect_frozen_child_templates(
    scenario: &Scenario,
) -> Result<Vec<FrozenChildTemplateSpec>, RunPlanError> {
    let mut templates = Vec::new();

    for (_, component) in scenario.components_iter() {
        templates.extend(component.child_templates.values().map(|template| {
            FrozenChildTemplateSpec {
                manifest: template.manifest.clone(),
                allowed_manifests: template.allowed_manifests.clone(),
                possible_backends: template.possible_backends.clone(),
            }
        }));
    }

    for entry in scenario.manifest_catalog.values() {
        let base_url = Url::parse(&entry.source_ref).map_err(|err| {
            RunPlanError::Other(format!(
                "failed to parse frozen manifest catalog source_ref `{}`: {err}",
                entry.source_ref
            ))
        })?;
        for template in entry.manifest.child_templates().values() {
            templates.push(freeze_manifest_child_template(
                &scenario.manifest_catalog,
                &base_url,
                template,
            )?);
        }
    }

    Ok(templates)
}

fn freeze_manifest_child_template(
    catalog: &BTreeMap<String, amber_scenario::ManifestCatalogEntry>,
    base_url: &Url,
    template: &ChildTemplateDecl,
) -> Result<FrozenChildTemplateSpec, RunPlanError> {
    let manifest = template
        .manifest
        .as_ref()
        .map(|manifest| resolve_catalog_key(base_url, manifest, catalog))
        .transpose()?;
    let allowed_manifests = match template.allowed_manifests.as_ref() {
        Some(ChildTemplateAllowedManifests::Refs(refs)) => Some(
            refs.iter()
                .map(|manifest| resolve_catalog_key(base_url, manifest, catalog))
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(ChildTemplateAllowedManifests::Selector(selector)) => {
            Some(expand_catalog_selector(catalog, base_url, selector)?)
        }
        None => None,
        Some(_) => {
            return Err(RunPlanError::Other(
                "unsupported frozen child-template allowed_manifests shape".to_string(),
            ));
        }
    };

    Ok(FrozenChildTemplateSpec {
        manifest,
        allowed_manifests,
        possible_backends: template.possible_backends.clone(),
    })
}

fn resolve_catalog_key(
    base_url: &Url,
    manifest: &ManifestRef,
    catalog: &BTreeMap<String, amber_scenario::ManifestCatalogEntry>,
) -> Result<String, RunPlanError> {
    let resolved = manifest.resolve_against(base_url).map_err(|err| {
        RunPlanError::Other(format!(
            "failed to resolve manifest ref `{:?}`: {err}",
            manifest
        ))
    })?;
    let key = resolved
        .url
        .as_url()
        .expect("resolved manifest refs are absolute");
    let key = key.to_string();
    if catalog.contains_key(&key) {
        Ok(key)
    } else {
        Err(RunPlanError::Other(format!(
            "frozen manifest catalog is missing `{key}`"
        )))
    }
}

fn expand_catalog_selector(
    catalog: &BTreeMap<String, amber_scenario::ManifestCatalogEntry>,
    base_url: &Url,
    selector: &amber_manifest::ChildTemplateManifestSelector,
) -> Result<Vec<String>, RunPlanError> {
    let root = base_url.join(&selector.root).map_err(|err| {
        RunPlanError::Other(format!(
            "failed to resolve selector root `{}`: {err}",
            selector.root
        ))
    })?;
    let include_patterns = if selector.include.is_empty() {
        vec![Pattern::new("**/*.json5").expect("default selector pattern should compile")]
    } else {
        selector
            .include
            .iter()
            .map(|pattern| {
                Pattern::new(pattern).map_err(|err| {
                    RunPlanError::Other(format!(
                        "invalid selector include pattern `{pattern}`: {err}"
                    ))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let exclude_patterns = selector
        .exclude
        .iter()
        .map(|pattern| {
            Pattern::new(pattern).map_err(|err| {
                RunPlanError::Other(format!(
                    "invalid selector exclude pattern `{pattern}`: {err}"
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut matches = catalog
        .values()
        .filter_map(|entry| {
            let entry_url = Url::parse(&entry.source_ref).ok()?;
            let relative = relative_catalog_path(&root, &entry_url)?;
            include_patterns
                .iter()
                .any(|pattern| pattern.matches(&relative))
                .then_some((relative, entry.source_ref.clone()))
        })
        .filter(|(relative, _)| {
            !exclude_patterns
                .iter()
                .any(|pattern| pattern.matches(relative.as_str()))
        })
        .map(|(_, source_ref)| source_ref)
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();

    if matches.is_empty() {
        return Err(RunPlanError::Other(format!(
            "selector rooted at `{}` matched no frozen manifests",
            root
        )));
    }

    Ok(matches)
}

fn relative_catalog_path(root: &Url, candidate: &Url) -> Option<String> {
    if root.scheme() != candidate.scheme()
        || root.host_str() != candidate.host_str()
        || root.port_or_known_default() != candidate.port_or_known_default()
    {
        return None;
    }

    let root_segments = root.path_segments()?.collect::<Vec<_>>();
    let candidate_segments = candidate.path_segments()?.collect::<Vec<_>>();
    if candidate_segments.len() < root_segments.len() {
        return None;
    }
    if !candidate_segments.starts_with(&root_segments) {
        return None;
    }

    let relative = candidate_segments[root_segments.len()..].join("/");
    (!relative.is_empty()).then_some(relative)
}

fn analyze_manifest_root_sites(
    catalog: &BTreeMap<String, amber_scenario::ManifestCatalogEntry>,
    site_definitions: &BTreeMap<String, SiteDefinition>,
    defaults: &PlacementDefaults,
    root_key: &str,
) -> Result<BTreeSet<String>, RunPlanError> {
    let mut analyzer = FragmentAnalyzer {
        catalog,
        site_definitions,
        defaults,
        required_sites: BTreeSet::new(),
        storage_sites: BTreeMap::new(),
    };
    analyzer.walk(root_key, "/".to_string(), &FragmentContext::default())?;

    for (identity, sites_for_identity) in analyzer.storage_sites {
        if sites_for_identity.len() <= 1 {
            continue;
        }
        let sites = sites_for_identity.into_iter().collect::<Vec<_>>();
        return Err(RunPlanError::Other(format!(
            "frozen template fragment rooted at `{root_key}` mounts one storage source across \
             multiple sites: {identity:?} on {sites:?}"
        )));
    }

    Ok(analyzer.required_sites)
}

impl FragmentAnalyzer<'_> {
    fn walk(
        &mut self,
        key: &str,
        moniker: String,
        context: &FragmentContext,
    ) -> Result<(), RunPlanError> {
        let entry = self.catalog.get(key).ok_or_else(|| {
            RunPlanError::Other(format!("frozen manifest catalog is missing `{key}`"))
        })?;
        let manifest = &entry.manifest;

        if let Some(program) = manifest.program() {
            let site_id = resolve_manifest_program_site(
                &moniker,
                program,
                self.site_definitions,
                self.defaults,
            )?;
            self.required_sites.insert(site_id.clone());
            for mount in program.mounts() {
                let Some(source) = mount.literal_source() else {
                    continue;
                };
                let identity = match source {
                    MountSource::Resource(resource)
                        if manifest
                            .resources()
                            .get(resource.as_str())
                            .is_some_and(|decl| decl.kind == CapabilityKind::Storage) =>
                    {
                        Some(StorageIdentityKey::Resource {
                            owner: moniker.clone(),
                            resource,
                        })
                    }
                    MountSource::Slot(slot)
                        if manifest
                            .slots()
                            .get(slot.as_str())
                            .is_some_and(|decl| decl.decl.kind == CapabilityKind::Storage) =>
                    {
                        Some(
                            context
                                .storage_slots
                                .get(slot.as_str())
                                .cloned()
                                .unwrap_or_else(|| StorageIdentityKey::ExternalSlot {
                                    owner: moniker.clone(),
                                    slot,
                                }),
                        )
                    }
                    MountSource::Config(_)
                    | MountSource::Framework(_)
                    | MountSource::Resource(_)
                    | MountSource::Slot(_)
                    | _ => None,
                };
                if let Some(identity) = identity {
                    self.storage_sites
                        .entry(identity)
                        .or_default()
                        .insert(site_id.clone());
                }
            }
        }

        let mut child_contexts = BTreeMap::<String, FragmentContext>::new();
        for binding in manifest.bindings() {
            let ManifestBindingTarget::ChildSlot { child, slot } = &binding.target else {
                continue;
            };
            let Some(identity) = storage_identity_for_binding_source(
                manifest,
                &moniker,
                context,
                &binding.binding.from,
            ) else {
                continue;
            };
            child_contexts
                .entry(child.to_string())
                .or_default()
                .storage_slots
                .insert(slot.to_string(), identity);
        }

        let base_url = Url::parse(&entry.source_ref).map_err(|err| {
            RunPlanError::Other(format!(
                "failed to parse frozen manifest catalog source_ref `{}`: {err}",
                entry.source_ref
            ))
        })?;
        for (child_name, child_decl) in manifest.components() {
            let child_ref = component_manifest_ref(child_decl);
            let child_key = resolve_catalog_key(&base_url, child_ref, self.catalog)?;
            let child_moniker = if moniker == "/" {
                format!("/{}", child_name)
            } else {
                format!("{moniker}/{}", child_name)
            };
            let child_context = child_contexts
                .remove(child_name.as_str())
                .unwrap_or_default();
            self.walk(&child_key, child_moniker, &child_context)?;
        }

        Ok(())
    }
}

fn storage_identity_for_binding_source(
    manifest: &Manifest,
    moniker: &str,
    context: &FragmentContext,
    source: &ManifestBindingSource,
) -> Option<StorageIdentityKey> {
    match source {
        ManifestBindingSource::Resource(resource)
            if manifest
                .resources()
                .get(resource.as_str())
                .is_some_and(|decl| decl.kind == CapabilityKind::Storage) =>
        {
            Some(StorageIdentityKey::Resource {
                owner: moniker.to_string(),
                resource: resource.to_string(),
            })
        }
        ManifestBindingSource::SelfSlot(slot)
            if manifest
                .slots()
                .get(slot.as_str())
                .is_some_and(|decl| decl.decl.kind == CapabilityKind::Storage) =>
        {
            Some(
                context
                    .storage_slots
                    .get(slot.as_str())
                    .cloned()
                    .unwrap_or_else(|| StorageIdentityKey::ExternalSlot {
                        owner: moniker.to_string(),
                        slot: slot.to_string(),
                    }),
            )
        }
        ManifestBindingSource::SelfProvide(_)
        | ManifestBindingSource::ChildExport { .. }
        | ManifestBindingSource::Framework(_)
        | _ => None,
    }
}

fn component_manifest_ref(component: &ComponentDecl) -> &ManifestRef {
    match component {
        ComponentDecl::Reference(manifest) => manifest,
        ComponentDecl::Object(component) => &component.manifest,
        _ => unreachable!("new component declaration kind requires run-plan support"),
    }
}

fn resolve_manifest_program_site(
    moniker: &str,
    program: &ManifestProgram,
    site_definitions: &BTreeMap<String, SiteDefinition>,
    defaults: &PlacementDefaults,
) -> Result<String, RunPlanError> {
    let site_id = match program {
        ManifestProgram::Path(_) => defaults.path.clone().ok_or(RunPlanError::MissingDefault {
            program_kind: "program.path",
        })?,
        ManifestProgram::Vm(_) => defaults.vm.clone().ok_or(RunPlanError::MissingDefault {
            program_kind: "program.vm",
        })?,
        ManifestProgram::Image(_) => {
            defaults.image.clone().ok_or(RunPlanError::MissingDefault {
                program_kind: "program.image",
            })?
        }
        _ => {
            return Err(RunPlanError::Other(format!(
                "component `{moniker}` uses an unsupported frozen program kind"
            )));
        }
    };
    let site = site_definitions
        .get(&site_id)
        .ok_or_else(|| RunPlanError::UnknownSite {
            site_id: site_id.clone(),
        })?;
    validate_manifest_program_support(moniker, &site_id, site, program)?;
    Ok(site_id)
}

fn validate_manifest_program_support(
    component: &str,
    site_id: &str,
    site: &SiteDefinition,
    program: &ManifestProgram,
) -> Result<(), RunPlanError> {
    match (site.kind, program) {
        (SiteKind::Direct, ManifestProgram::Path(_)) => Ok(()),
        (SiteKind::Vm, ManifestProgram::Vm(_)) => Ok(()),
        (SiteKind::Compose, ManifestProgram::Image(_))
        | (SiteKind::Kubernetes, ManifestProgram::Image(_)) => Ok(()),
        (SiteKind::Direct, _) => Err(RunPlanError::UnsupportedPlacement {
            component: component.to_string(),
            site_id: site_id.to_string(),
            kind: site.kind,
            supported: "program.path workloads",
        }),
        (SiteKind::Vm, _) => Err(RunPlanError::UnsupportedPlacement {
            component: component.to_string(),
            site_id: site_id.to_string(),
            kind: site.kind,
            supported: "program.vm workloads",
        }),
        (SiteKind::Compose, _) | (SiteKind::Kubernetes, _) => {
            Err(RunPlanError::UnsupportedPlacement {
                component: component.to_string(),
                site_id: site_id.to_string(),
                kind: site.kind,
                supported: "program.image workloads",
            })
        }
    }
}

fn site_kind_for_runtime_backend(backend: RuntimeBackend) -> SiteKind {
    match backend {
        RuntimeBackend::Direct => SiteKind::Direct,
        RuntimeBackend::Vm => SiteKind::Vm,
        RuntimeBackend::Compose => SiteKind::Compose,
        RuntimeBackend::Kubernetes => SiteKind::Kubernetes,
        _ => unreachable!("new runtime backend kind requires run-plan support"),
    }
}

fn build_cross_site_links(
    scenario: &Scenario,
    mesh_plan: &crate::targets::mesh::plan::MeshPlan,
    assignments_by_component: &BTreeMap<ComponentId, String>,
) -> Vec<RunLink> {
    let mut links = BTreeMap::<
        (
            String,
            String,
            String,
            String,
            String,
            String,
            NetworkProtocol,
        ),
        RunLink,
    >::new();

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
        let consumer_component = graph::component_path(scenario, binding.consumer);
        let key = (
            provider_site.clone(),
            consumer_site.clone(),
            export_name.clone(),
            external_slot_name.clone(),
            consumer_component.clone(),
            binding.slot.clone(),
            binding.endpoint.protocol,
        );
        links.entry(key).or_insert_with(|| RunLink {
            provider_site: provider_site.clone(),
            consumer_site: consumer_site.clone(),
            provider_component: graph::component_path(scenario, binding.provider),
            provide: binding.provide.clone(),
            consumer_component,
            slot: binding.slot.clone(),
            weak: binding.weak,
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
    active_sites: &[String],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut site_dependencies = BTreeMap::<String, BTreeSet<String>>::new();
    for site_id in active_sites {
        site_dependencies.entry(site_id.clone()).or_default();
    }
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

fn topo_waves(
    site_dependencies: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Vec<Vec<String>>, RunPlanError> {
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

    let blocked_sites = indegree
        .into_iter()
        .filter_map(|(site, degree)| (degree > 0).then_some(site))
        .collect::<Vec<_>>();
    if blocked_sites.is_empty() {
        Ok(waves)
    } else {
        Err(RunPlanError::CyclicSiteDependencies {
            sites: blocked_sites,
        })
    }
}

fn build_site_scenario(
    scenario: &Scenario,
    site_id: &str,
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
        if component.program.is_some()
            && assignments_by_component
                .get(&component_id)
                .is_none_or(|assigned_site| assigned_site != site_id)
        {
            component.program = None;
        }
        component
            .children
            .retain(|child| included_set.contains(child));
        components[component_id.0] = Some(component);
    }

    let retained_root_slots = scenario
        .bindings
        .iter()
        .filter_map(|binding| {
            let BindingFrom::External(slot) = &binding.from else {
                return None;
            };
            if slot.component != root_id || !included_set.contains(&binding.to.component) {
                return None;
            }
            components[binding.to.component.0]
                .as_ref()
                .and_then(|component| component.program.as_ref())
                .map(|_| slot.name.clone())
        })
        .collect::<BTreeSet<_>>();
    if let Some(root_component) = components[root_id.0].as_mut() {
        root_component
            .slots
            .retain(|name, _| retained_root_slots.contains(name));
        root_component.slots.extend(synthetic_slots.clone());
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
        let target_component = components[binding.to.component.0]
            .as_ref()
            .expect("included binding target should exist");
        if slot_decl.decl.kind != CapabilityKind::Storage && target_component.program.is_none() {
            continue;
        }
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
        manifest_catalog: scenario.manifest_catalog.clone(),
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
    force_router: bool,
) -> Result<BTreeMap<String, String>, RunPlanError> {
    let mut files = match site_kind {
        SiteKind::Direct => {
            crate::targets::direct::emit_direct_artifact(compiled, force_router)
                .map_err(|err| RunPlanError::Other(format!("failed to render direct site: {err}")))?
                .files
        }
        SiteKind::Vm => {
            crate::targets::vm::emit_vm_artifact(compiled, force_router)
                .map_err(|err| RunPlanError::Other(format!("failed to render vm site: {err}")))?
                .files
        }
        SiteKind::Compose => {
            crate::targets::mesh::docker_compose::emit_docker_compose_artifact(
                compiled,
                force_router,
            )
            .map_err(|err| RunPlanError::Other(format!("failed to render compose site: {err}")))?
            .files
        }
        SiteKind::Kubernetes => {
            crate::targets::mesh::kubernetes::emit_kubernetes_artifact(compiled, force_router)
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
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs,
        path::Path,
    };

    use amber_manifest::ManifestRef;
    use amber_resolver::Resolver;
    use tempfile::TempDir;
    use url::Url;

    use super::*;
    use crate::{
        CompileOptions, Compiler, DigestStore, ResolverRegistry, reporter::CompiledScenario,
    };

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

    fn dynamic_parent_manifest() -> &'static str {
        r#"{
  manifest_version: "0.3.0",
  slots: { realm: { kind: "component", optional: true } },
  child_templates: {
    worker: {
      manifest: "./worker.json5",
      bindings: { realm: "slots.realm" }
    }
  },
  program: {
    image: "busybox:1.36.1",
    entrypoint: ["sh", "-c", "sleep 30"],
    network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
  },
  provides: { api: { kind: "http", endpoint: "http" } },
  exports: { api: "api" }
}"#
    }

    fn dynamic_worker_manifest() -> &'static str {
        r#"{
  manifest_version: "0.3.0",
  slots: { realm: { kind: "component" } },
  program: {
    path: "/usr/bin/env",
    args: ["sh", "-c", "sleep 30"]
  }
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
    async fn exact_child_templates_activate_standby_sites_from_frozen_inputs() {
        let dir = tmp_dir("run-plan-standby-exact-template-");
        let worker = dir.path().join("worker.json5");
        let root = dir.path().join("root.json5");

        write(&worker, dynamic_worker_manifest());
        write(&root, dynamic_parent_manifest());

        let compiled = compile(&root).await;
        let plan = build_run_plan(&compiled, None).expect("run plan should build");
        assert_eq!(plan.standby_sites, vec!["direct_local".to_string()]);
        assert_eq!(
            plan.initial_active_sites,
            vec!["compose_local".to_string(), "direct_local".to_string()]
        );
        assert_eq!(
            plan.dynamic_enabled_sites,
            vec!["compose_local".to_string(), "direct_local".to_string()]
        );
        assert_eq!(plan.offered_sites["direct_local"].kind, SiteKind::Direct);
        assert_eq!(plan.defaults.path.as_deref(), Some("direct_local"));
        assert_eq!(
            plan.sites["compose_local"].assigned_components,
            vec!["/".to_string()]
        );
        assert_eq!(
            plan.sites["direct_local"].assigned_components,
            Vec::<String>::new()
        );
        assert!(
            plan.sites["direct_local"]
                .artifact_files
                .contains_key("run.sh")
        );
        let direct_plan: serde_json::Value = serde_json::from_str(
            plan.sites["direct_local"]
                .artifact_files
                .get("direct-plan.json")
                .expect("direct standby site should include a direct plan"),
        )
        .expect("direct standby plan should be valid json");
        assert!(
            direct_plan["router"].is_object(),
            "standby direct site should materialize a router substrate"
        );
        assert!(plan.active_site_capabilities["direct_local"].dynamic_workloads);

        let frozen = CompiledScenario::from_ir(compiled.scenario_ir().clone())
            .expect("scenario ir should round-trip");
        let frozen_plan = build_run_plan(&frozen, None).expect("frozen run plan should build");
        assert_eq!(frozen_plan.standby_sites, plan.standby_sites);
        assert_eq!(frozen_plan.initial_active_sites, plan.initial_active_sites);
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

    #[test]
    fn startup_waves_reject_cyclic_cross_site_dependencies() {
        let err = topo_waves(&BTreeMap::from([
            (
                "compose_b".to_string(),
                BTreeSet::from(["direct_a".to_string()]),
            ),
            (
                "direct_a".to_string(),
                BTreeSet::from(["compose_b".to_string()]),
            ),
        ]))
        .expect_err("cyclic site dependencies should fail planning");
        assert!(matches!(
            err,
            RunPlanError::CyclicSiteDependencies { ref sites }
                if sites == &vec!["compose_b".to_string(), "direct_a".to_string()]
        ));
    }

    #[tokio::test]
    async fn build_run_plan_preserves_repeated_cross_site_consumers() {
        let dir = tmp_dir("run-plan-repeated-cross-site-consumers-");
        let provider = dir.path().join("provider.json5");
        let a = dir.path().join("a.json5");
        let b = dir.path().join("b.json5");
        let root = dir.path().join("root.json5");

        write(&provider, image_server_manifest());
        for consumer in [&a, &b] {
            write(
                consumer,
                r#"{
  manifest_version: "0.3.0",
  slots: { upstream: { kind: "http" } },
  program: {
    path: "/usr/bin/env",
    args: ["sh", "-c", "sleep 30"],
    env: { UPSTREAM_URL: "${slots.upstream.url}" },
    network: { endpoints: [{ name: "http", port: 8080, protocol: "http" }] }
  },
  provides: { api: { kind: "http", endpoint: "http" } },
  exports: { api: "api" }
}"#,
            );
        }
        write(
            &root,
            r##"{
  manifest_version: "0.3.0",
  components: {
    provider: "./provider.json5",
    a: "./a.json5",
    b: "./b.json5"
  },
  bindings: [
    { from: "#provider.api", to: "#a.upstream" },
    { from: "#provider.api", to: "#b.upstream" }
  ],
  exports: {
    provider_api: "#provider.api",
    a_api: "#a.api",
    b_api: "#b.api"
  }
}"##,
        );

        let compiled = compile(&root).await;
        let scenario = compiled.scenario();
        let endpoint_plan = build_endpoint_plan(scenario).expect("endpoint plan should build");
        let mesh_plan = build_mesh_plan(
            scenario,
            &endpoint_plan,
            MeshOptions {
                backend_label: "test",
            },
        )
        .expect("mesh plan should build");
        let assignments = scenario
            .components_iter()
            .filter_map(
                |(component_id, component)| match component.moniker.as_str() {
                    "/provider" => Some((component_id, "compose_provider".to_string())),
                    "/a" | "/b" => Some((component_id, "direct_consumers".to_string())),
                    _ => None,
                },
            )
            .collect::<BTreeMap<_, _>>();

        let links = build_cross_site_links(scenario, &mesh_plan, &assignments);
        let consumer_links = links
            .iter()
            .filter(|link| link.consumer_site == "direct_consumers")
            .collect::<Vec<_>>();
        assert_eq!(consumer_links.len(), 2);
        assert_eq!(
            consumer_links
                .iter()
                .map(|link| link.consumer_component.as_str())
                .collect::<Vec<_>>(),
            vec!["/a", "/b"]
        );
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

    #[tokio::test]
    async fn build_unmanaged_export_uses_single_matching_site() {
        let dir = tmp_dir("run-plan-unmanaged-export-single-");
        let image_child = dir.path().join("image.json5");
        let root = dir.path().join("root.json5");

        write(&image_child, image_server_manifest());
        write(
            &root,
            r##"{
  manifest_version: "0.3.0",
  components: {
    image: "./image.json5"
  },
  exports: {
    image_api: "#image.api"
  }
}"##,
        );

        let compiled = compile(&root).await;
        let plan = build_run_plan(&compiled, None).expect("run plan should build");
        let export = build_unmanaged_export(&plan, SiteKind::Compose).expect("export should build");
        assert_eq!(export.site_id, "compose_local");
        assert!(export.files.contains_key(&PathBuf::from("compose.yaml")));
    }

    #[tokio::test]
    async fn build_unmanaged_export_rejects_mixed_site_plans() {
        let dir = tmp_dir("run-plan-unmanaged-export-mixed-");
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
        let err = build_unmanaged_export(&plan, SiteKind::Compose)
            .expect_err("mixed-site export should fail");
        let rendered = err.to_string();
        assert!(rendered.contains("single compose site"), "{rendered}");
        assert!(rendered.contains("`direct_local` (direct)"), "{rendered}");
        assert!(rendered.contains("`compose_local` (compose)"), "{rendered}");
    }

    #[tokio::test]
    async fn build_homogeneous_export_run_plan_targets_requested_kind_without_placement() {
        let dir = tmp_dir("run-plan-homogeneous-export-");
        let image_child = dir.path().join("image.json5");
        let root = dir.path().join("root.json5");

        write(&image_child, image_server_manifest());
        write(
            &root,
            r##"{
  manifest_version: "0.3.0",
  components: {
    image: "./image.json5"
  },
  exports: {
    image_api: "#image.api"
  }
}"##,
        );

        let compiled = compile(&root).await;
        let plan = build_homogeneous_export_run_plan(&compiled, SiteKind::Kubernetes)
            .expect("homogeneous export plan should build");
        let site = plan
            .sites
            .get("kubernetes_local")
            .expect("kubernetes export site should exist");
        assert_eq!(site.site.kind, SiteKind::Kubernetes);

        let export =
            build_unmanaged_export(&plan, SiteKind::Kubernetes).expect("export should build");
        assert_eq!(export.site_id, "kubernetes_local");
        assert!(
            export
                .files
                .contains_key(&PathBuf::from("kustomization.yaml"))
        );
    }
}
