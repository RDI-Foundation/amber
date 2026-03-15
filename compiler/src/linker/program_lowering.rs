use std::collections::{BTreeMap, BTreeSet};

use amber_config as rc;
use amber_manifest::{
    CapabilityKind, ConfigSchema, Endpoint as ManifestEndpoint, EndpointPort, ExperimentalFeature,
    FrameworkCapabilityName, InterpolatedPart, InterpolatedString, InterpolationSource,
    MountSource, Program as ManifestProgram, ProgramMount as ManifestMount, ResourceDecl,
    ResourceName, SlotDecl, SlotName, WhenPath, framework_capability,
};
use amber_scenario::{
    ComponentId, Endpoint, FileMount, FileMountSource, Program, ProgramCommon, ProgramCondition,
    ProgramEach, ProgramImage, ProgramMount, ProgramNetwork, ProgramPath, ProgramVm,
};
use amber_template::{TemplatePart, TemplateString};
use serde_json::Value;

use crate::config::{
    analysis::ComponentConfigAnalysis,
    query::{ConfigEachResolution, ConfigPresence},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProgramLoweringSite {
    Endpoint(usize),
    Mount(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProgramLoweringError {
    pub(crate) site: ProgramLoweringSite,
    pub(crate) message: String,
}

#[derive(Clone, Copy, Debug)]
enum ItemLowering<'a> {
    None,
    Static(&'a Value),
    CurrentItem,
}

#[derive(Clone, Debug)]
enum LoweredMountSource {
    File(FileMountSource),
    Slot(String),
    Resource(String),
    Framework(amber_manifest::FrameworkCapabilityName),
}

#[derive(Clone, Debug)]
enum LoweredWhen {
    Present,
    Absent,
    Runtime(ProgramCondition),
}

#[derive(Clone, Debug)]
pub(crate) struct LoweredProgram {
    pub(crate) program: Program,
    pub(crate) mount_source_indices: Vec<usize>,
}

#[derive(Clone, Debug)]
struct LoweredCommon {
    common: ProgramCommon,
    mount_source_indices: Vec<usize>,
}

#[derive(Clone, Debug)]
struct LoweredMounts {
    mounts: Vec<ProgramMount>,
    source_indices: Vec<usize>,
}

#[cfg(test)]
pub(crate) fn lower_program(
    component_id: ComponentId,
    program: &ManifestProgram,
    template_opt: Option<&rc::ConfigNode>,
) -> Result<Program, Vec<ProgramLoweringError>> {
    Ok(lower_program_with_origins(component_id, program, template_opt)?.program)
}

#[cfg(test)]
pub(crate) fn lower_program_with_origins(
    component_id: ComponentId,
    program: &ManifestProgram,
    template_opt: Option<&rc::ConfigNode>,
) -> Result<LoweredProgram, Vec<ProgramLoweringError>> {
    let component_config = ComponentConfigAnalysis::standalone(template_opt.cloned(), None, None)
        .expect("test config analysis should build");
    lower_program_with_config_analysis(component_id, program, &component_config)
}

#[cfg(test)]
pub(crate) fn lower_program_with_origins_and_root_schema(
    component_id: ComponentId,
    program: &ManifestProgram,
    template_opt: Option<&rc::ConfigNode>,
    root_schema: Option<&Value>,
) -> Result<LoweredProgram, Vec<ProgramLoweringError>> {
    let component_config =
        ComponentConfigAnalysis::standalone(template_opt.cloned(), None, root_schema.cloned())
            .expect("test config analysis should build");
    lower_program_with_config_analysis(component_id, program, &component_config)
}

pub(crate) fn lower_program_with_config_analysis(
    component_id: ComponentId,
    program: &ManifestProgram,
    component_config: &ComponentConfigAnalysis,
) -> Result<LoweredProgram, Vec<ProgramLoweringError>> {
    match program {
        ManifestProgram::Image(program) => {
            let common = lower_common(
                component_id,
                &program.common,
                component_config,
                "program.network.endpoints",
                "program.mounts",
            )?;
            Ok(LoweredProgram {
                program: Program::Image(ProgramImage {
                    image: program.image.clone(),
                    entrypoint: program.entrypoint.clone(),
                    common: common.common,
                }),
                mount_source_indices: common.mount_source_indices,
            })
        }
        ManifestProgram::Path(program) => {
            let common = lower_common(
                component_id,
                &program.common,
                component_config,
                "program.network.endpoints",
                "program.mounts",
            )?;
            Ok(LoweredProgram {
                program: Program::Path(ProgramPath {
                    path: program.path.clone(),
                    args: program.args.clone(),
                    common: common.common,
                }),
                mount_source_indices: common.mount_source_indices,
            })
        }
        ManifestProgram::Vm(program) => {
            let network = lower_network(
                program
                    .0
                    .network
                    .as_ref()
                    .map_or(&[], |network| network.endpoints.as_slice()),
                component_config,
                "program.vm.network.endpoints",
            )?;
            let mounts = lower_mounts(
                component_id,
                &program.0.mounts,
                component_config,
                "program.vm.mounts",
            )?;
            Ok(LoweredProgram {
                program: Program::Vm(ProgramVm {
                    image: program.0.image.clone(),
                    cpus: program.0.cpus.clone(),
                    memory_mib: program.0.memory_mib.clone(),
                    network,
                    mounts: mounts.mounts,
                    cloud_init: program.0.cloud_init.clone(),
                    egress: program
                        .0
                        .network
                        .as_ref()
                        .map_or_else(Default::default, |network| network.egress),
                }),
                mount_source_indices: mounts.source_indices,
            })
        }
        _ => unreachable!("unsupported manifest program variant"),
    }
}

pub(crate) fn validate_lowered_program_mounts(
    program: &Program,
    mount_source_indices: &[usize],
    config_schema: Option<&ConfigSchema>,
    resources: &BTreeMap<ResourceName, ResourceDecl>,
    slots: &BTreeMap<SlotName, SlotDecl>,
    enabled_features: &BTreeSet<ExperimentalFeature>,
) -> Result<(), Vec<ProgramLoweringError>> {
    let mut errors = Vec::new();
    let mut seen_paths = BTreeSet::new();

    for (lowered_index, mount) in program.mounts().iter().enumerate() {
        let authored_index = mount_source_indices[lowered_index];
        if let Some(message) =
            validate_lowered_mount(mount, config_schema, resources, slots, enabled_features)
        {
            errors.push(ProgramLoweringError {
                site: ProgramLoweringSite::Mount(authored_index),
                message,
            });
            continue;
        }

        if let Some(path) = lowered_mount_static_path(mount)
            && !seen_paths.insert(path.clone())
        {
            errors.push(ProgramLoweringError {
                site: ProgramLoweringSite::Mount(authored_index),
                message: format!("duplicate mount path `{path}` after mount expansion"),
            });
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_lowered_mount(
    mount: &ProgramMount,
    config_schema: Option<&ConfigSchema>,
    resources: &BTreeMap<ResourceName, ResourceDecl>,
    slots: &BTreeMap<SlotName, SlotDecl>,
    enabled_features: &BTreeSet<ExperimentalFeature>,
) -> Option<String> {
    match mount {
        ProgramMount::File(file_mount) => validate_lowered_file_mount(file_mount, config_schema),
        ProgramMount::Slot { slot, .. } => match slots.get(slot.as_str()) {
            Some(slot_decl) if slot_decl.decl.kind == CapabilityKind::Storage => None,
            Some(slot_decl) => Some(format!(
                "mount source resolved to `slots.{slot}`, but `{slot}` is `{}` instead of \
                 `storage`",
                slot_decl.decl.kind
            )),
            None => Some(format!(
                "mount source resolved to `slots.{slot}`, but no such slot exists on the component"
            )),
        },
        ProgramMount::Resource { resource, .. } => (!resources.contains_key(resource.as_str()))
            .then(|| {
                format!(
                    "mount source resolved to `resources.{resource}`, but no such resource exists \
                     on the component"
                )
            }),
        ProgramMount::Framework { capability, .. } => {
            validate_lowered_framework_mount(capability, enabled_features)
        }
    }
}

fn validate_lowered_file_mount(
    mount: &FileMount,
    config_schema: Option<&ConfigSchema>,
) -> Option<String> {
    if let Some(path) = render_template_string_static_opt(&mount.path)
        && let Err(message) = validate_static_mount_path(&path)
    {
        return Some(format!("{message}: `{path}`"));
    }

    let Some(component_schema) = config_schema.map(|schema| &schema.0) else {
        return Some(format!(
            "mount source `{}` requires `config_schema`, but the component does not declare one",
            describe_file_mount_source(&mount.source)
        ));
    };

    let source = render_static_file_mount_source(&mount.source)?;
    let source = rc::parse_rendered_file_mount_source(&source)
        .expect("lowering should only produce valid rendered file mount sources");
    rc::validate_rendered_file_mount_source(component_schema, source)
        .err()
        .map(|err| err.to_string())
}

fn validate_lowered_framework_mount(
    capability: &FrameworkCapabilityName,
    enabled_features: &BTreeSet<ExperimentalFeature>,
) -> Option<String> {
    let Some(spec) = framework_capability(capability.as_str()) else {
        return Some(format!(
            "mount source resolved to unknown framework capability `framework.{capability}`"
        ));
    };

    let required = spec.required_experimental_feature?;
    (!enabled_features.contains(&required)).then(|| {
        format!(
            "framework capability `framework.{capability}` requires experimental feature \
             `{required}`"
        )
    })
}

fn lowered_mount_static_path(mount: &ProgramMount) -> Option<String> {
    match mount {
        ProgramMount::File(file_mount) => render_template_string_static_opt(&file_mount.path),
        ProgramMount::Slot { path, .. }
        | ProgramMount::Resource { path, .. }
        | ProgramMount::Framework { path, .. } => Some(path.clone()),
    }
}

fn describe_file_mount_source(source: &FileMountSource) -> String {
    render_static_file_mount_source(source).unwrap_or_else(|| match source {
        FileMountSource::Config { .. } => "config.<dynamic path>".to_string(),
    })
}

fn render_static_file_mount_source(source: &FileMountSource) -> Option<String> {
    match source {
        FileMountSource::Config { path } => Some(render_prefixed_mount_source(
            "config",
            render_template_string_static_opt(path)?,
        )),
    }
}

fn render_prefixed_mount_source(prefix: &str, path: String) -> String {
    if path.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}.{path}")
    }
}

fn validate_static_mount_path(path: &str) -> Result<(), &'static str> {
    if !path.starts_with('/') {
        return Err("mount path must be absolute");
    }
    if path.split('/').any(|segment| segment == "..") {
        return Err("mount path must not contain `..`");
    }
    Ok(())
}

fn lower_common(
    component_id: ComponentId,
    common: &amber_manifest::ProgramCommon,
    component_config: &ComponentConfigAnalysis,
    network_location_prefix: &str,
    mount_location_prefix: &str,
) -> Result<LoweredCommon, Vec<ProgramLoweringError>> {
    let network = lower_network(
        common
            .network
            .as_ref()
            .map_or(&[], |network| network.endpoints.as_slice()),
        component_config,
        network_location_prefix,
    )?;
    let mounts = lower_mounts(
        component_id,
        &common.mounts,
        component_config,
        mount_location_prefix,
    )?;
    Ok(LoweredCommon {
        common: ProgramCommon {
            env: common.env.clone(),
            network,
            mounts: mounts.mounts,
        },
        mount_source_indices: mounts.source_indices,
    })
}

fn lower_network(
    endpoints: &[ManifestEndpoint],
    component_config: &ComponentConfigAnalysis,
    location_prefix: &str,
) -> Result<Option<ProgramNetwork>, Vec<ProgramLoweringError>> {
    if endpoints.is_empty() {
        return Ok(None);
    }

    let mut lowered = Vec::new();
    let mut seen_names = std::collections::BTreeSet::new();
    let mut errors = Vec::new();

    for (index, endpoint) in endpoints.iter().enumerate() {
        let when = match lower_endpoint_when(endpoint.when.as_ref(), component_config) {
            Ok(when) => when,
            Err(message) => {
                errors.push(ProgramLoweringError {
                    site: ProgramLoweringSite::Endpoint(index),
                    message,
                });
                continue;
            }
        };
        if matches!(when, LoweredWhen::Absent) {
            continue;
        }

        let location = format!("{location_prefix}[{index}]");
        let mut emit = |item: Option<&Value>| match lower_endpoint(
            endpoint,
            component_config,
            item,
            &location,
        ) {
            Ok(lowered_endpoint) => {
                if !seen_names.insert(lowered_endpoint.name.clone()) {
                    errors.push(ProgramLoweringError {
                        site: ProgramLoweringSite::Endpoint(index),
                        message: format!(
                            "duplicate endpoint name `{}` after endpoint expansion",
                            lowered_endpoint.name
                        ),
                    });
                    return;
                }
                lowered.push(lowered_endpoint);
            }
            Err(message) => errors.push(ProgramLoweringError {
                site: ProgramLoweringSite::Endpoint(index),
                message,
            }),
        };

        match endpoint.each.as_ref() {
            None => emit(None),
            Some(each) => match each.source() {
                InterpolationSource::Config => {
                    match component_config.resolve_each_values(each.query(), &location) {
                        Ok(ConfigEachResolution::Static(items)) => {
                            for item in &items {
                                emit(Some(item));
                            }
                        }
                        Ok(ConfigEachResolution::Runtime) => {
                            errors.push(ProgramLoweringError {
                                site: ProgramLoweringSite::Endpoint(index),
                                message: "depends on runtime config, but endpoints must resolve \
                                          entirely at compile time"
                                    .to_string(),
                            });
                        }
                        Err(message) => errors.push(ProgramLoweringError {
                            site: ProgramLoweringSite::Endpoint(index),
                            message,
                        }),
                    }
                }
                InterpolationSource::Slots => errors.push(ProgramLoweringError {
                    site: ProgramLoweringSite::Endpoint(index),
                    message: format!(
                        "uses `each: \"{}\"`, but endpoints cannot depend on slots because port \
                         allocation happens before slot values exist",
                        each
                    ),
                }),
                InterpolationSource::Item => unreachable!("endpoint each never uses item"),
                _ => unreachable!("unsupported interpolation source for endpoint each"),
            },
        }
    }

    if errors.is_empty() {
        Ok((!lowered.is_empty()).then_some(ProgramNetwork { endpoints: lowered }))
    } else {
        Err(errors)
    }
}

fn lower_endpoint_when(
    when: Option<&WhenPath>,
    component_config: &ComponentConfigAnalysis,
) -> Result<LoweredWhen, String> {
    let Some(when) = when else {
        return Ok(LoweredWhen::Present);
    };

    match when.source() {
        InterpolationSource::Config => match component_config.resolve_presence(when.query())? {
            ConfigPresence::Present => Ok(LoweredWhen::Present),
            ConfigPresence::Absent => Ok(LoweredWhen::Absent),
            ConfigPresence::Runtime => Err("depends on runtime config, but endpoints must \
                                            resolve entirely at compile time"
                .to_string()),
        },
        InterpolationSource::Slots => Err(format!(
            "uses `when: \"{}\"`, but endpoints cannot depend on slots because port allocation \
             happens before slot values exist",
            when
        )),
        InterpolationSource::Item => unreachable!("when paths never use item"),
        _ => unreachable!("unsupported interpolation source for endpoint when"),
    }
}

fn lower_endpoint(
    endpoint: &ManifestEndpoint,
    component_config: &ComponentConfigAnalysis,
    item: Option<&Value>,
    location: &str,
) -> Result<Endpoint, String> {
    let name = lower_endpoint_string(location, "name", &endpoint.name, component_config, item)?;
    if name.is_empty() {
        return Err(format!("{location}.name resolves to an empty string"));
    }
    let protocol = lower_endpoint_string(
        location,
        "protocol",
        &endpoint.protocol,
        component_config,
        item,
    )?
    .parse::<amber_manifest::NetworkProtocol>()
    .map_err(|err| err.to_string())?;
    let port = match &endpoint.port {
        EndpointPort::Literal(port) => *port,
        EndpointPort::Interpolated(value) => {
            lower_endpoint_string(location, "port", value, component_config, item)?
                .parse::<u16>()
                .map_err(|err| err.to_string())?
        }
        _ => unreachable!("unsupported endpoint port variant"),
    };

    Ok(Endpoint {
        name,
        port,
        protocol,
    })
}

fn lower_endpoint_string(
    location: &str,
    field: &str,
    value: &InterpolatedString,
    component_config: &ComponentConfigAnalysis,
    item: Option<&Value>,
) -> Result<String, String> {
    let mut rendered = String::new();
    for part in &value.parts {
        match part {
            InterpolatedPart::Literal(lit) => rendered.push_str(lit),
            InterpolatedPart::Interpolation { source, query } => match source {
                InterpolationSource::Config => {
                    match resolve_config_string(component_config, query)? {
                        Some(value) => rendered.push_str(&value),
                        None => {
                            return Err(format!(
                                "{location}.{field} depends on runtime config, but endpoints must \
                                 resolve entirely at compile time"
                            ));
                        }
                    }
                }
                InterpolationSource::Item => {
                    let item = item.ok_or_else(|| {
                        format!(
                            "`item` interpolation is only valid inside repeated endpoint \
                             expansions in {location}.{field}"
                        )
                    })?;
                    rendered.push_str(&resolve_item_interpolation(item, query, location, field)?);
                }
                InterpolationSource::Slots => {
                    let label = if query.is_empty() {
                        "slots".to_string()
                    } else {
                        format!("slots.{query}")
                    };
                    return Err(format!(
                        "{location}.{field} references `{label}`, but endpoints cannot depend on \
                         slots because port allocation happens before slot values exist"
                    ));
                }
                _ => unreachable!("unsupported interpolation source in endpoint"),
            },
            _ => unreachable!("unsupported interpolation part in endpoint"),
        }
    }
    Ok(rendered)
}

fn lower_mounts(
    component_id: ComponentId,
    mounts: &[ManifestMount],
    component_config: &ComponentConfigAnalysis,
    location_prefix: &str,
) -> Result<LoweredMounts, Vec<ProgramLoweringError>> {
    let mut lowered = Vec::new();
    let mut source_indices = Vec::new();
    let mut errors = Vec::new();

    for (index, mount) in mounts.iter().enumerate() {
        let when = match lower_mount_when(mount.when.as_ref(), component_config) {
            Ok(when) => when,
            Err(message) => {
                errors.push(ProgramLoweringError {
                    site: ProgramLoweringSite::Mount(index),
                    message,
                });
                continue;
            }
        };
        if matches!(when, LoweredWhen::Absent) {
            continue;
        }

        let runtime_when = match &when {
            LoweredWhen::Present | LoweredWhen::Absent => None,
            LoweredWhen::Runtime(condition) => Some(condition.clone()),
        };
        let location = format!("{location_prefix}[{index}]");

        let mut emit = |item: ItemLowering<'_>, runtime_each: Option<ProgramEach>| {
            match lower_mount_iteration(
                component_id,
                mount,
                component_config,
                item,
                runtime_when.clone(),
                runtime_each,
                &location,
            ) {
                Ok(Some(lowered_mount)) => {
                    lowered.push(lowered_mount);
                    source_indices.push(index);
                }
                Ok(None) => {}
                Err(message) => errors.push(ProgramLoweringError {
                    site: ProgramLoweringSite::Mount(index),
                    message,
                }),
            }
        };

        match mount.each.as_ref() {
            None => emit(ItemLowering::None, None),
            Some(each) => match each.source() {
                InterpolationSource::Config => {
                    match component_config.resolve_each_values(each.query(), &location) {
                        Ok(ConfigEachResolution::Static(items)) => {
                            for item in &items {
                                emit(ItemLowering::Static(item), None);
                            }
                        }
                        Ok(ConfigEachResolution::Runtime) => emit(
                            ItemLowering::CurrentItem,
                            Some(ProgramEach::Config {
                                path: each.query().to_string(),
                            }),
                        ),
                        Err(message) => errors.push(ProgramLoweringError {
                            site: ProgramLoweringSite::Mount(index),
                            message,
                        }),
                    }
                }
                InterpolationSource::Slots => emit(
                    ItemLowering::CurrentItem,
                    Some(ProgramEach::Slot {
                        slot: each
                            .slot()
                            .expect("slot-based each path should expose a slot")
                            .to_string(),
                    }),
                ),
                InterpolationSource::Item => unreachable!("mount each never uses item"),
                _ => unreachable!("unsupported interpolation source for mount each"),
            },
        }
    }

    if errors.is_empty() {
        Ok(LoweredMounts {
            mounts: lowered,
            source_indices,
        })
    } else {
        Err(errors)
    }
}

fn lower_mount_when(
    when: Option<&WhenPath>,
    component_config: &ComponentConfigAnalysis,
) -> Result<LoweredWhen, String> {
    let Some(when) = when else {
        return Ok(LoweredWhen::Present);
    };

    match when.source() {
        InterpolationSource::Config => match component_config.resolve_presence(when.query())? {
            ConfigPresence::Present => Ok(LoweredWhen::Present),
            ConfigPresence::Absent => Ok(LoweredWhen::Absent),
            ConfigPresence::Runtime => Ok(LoweredWhen::Runtime(ProgramCondition::Config {
                path: when.query().to_string(),
            })),
        },
        InterpolationSource::Slots => Ok(LoweredWhen::Runtime(ProgramCondition::Slot {
            query: when.query().to_string(),
        })),
        InterpolationSource::Item => unreachable!("when paths never use item"),
        _ => unreachable!("unsupported interpolation source for mount when"),
    }
}

fn lower_mount_iteration(
    component_id: ComponentId,
    mount: &ManifestMount,
    component_config: &ComponentConfigAnalysis,
    item: ItemLowering<'_>,
    when: Option<ProgramCondition>,
    each: Option<ProgramEach>,
    location: &str,
) -> Result<Option<ProgramMount>, String> {
    let path = lower_template_string(
        component_id,
        &format!("{location}.path"),
        &mount.path,
        component_config,
        item,
    )?;
    let source = lower_template_string(
        component_id,
        &format!("{location}.from"),
        &mount.source,
        component_config,
        item,
    )?;
    let source = classify_mount_source(source)?;

    match source {
        LoweredMountSource::File(source) => Ok(Some(ProgramMount::File(FileMount {
            when,
            each,
            path,
            source,
        }))),
        LoweredMountSource::Slot(slot) => {
            let path = ensure_concrete_non_file_mount(
                &path,
                when.as_ref(),
                each.as_ref(),
                location,
                &format!("slots.{slot}"),
            )?;
            Ok(Some(ProgramMount::Slot { path, slot }))
        }
        LoweredMountSource::Resource(resource) => {
            let path = ensure_concrete_non_file_mount(
                &path,
                when.as_ref(),
                each.as_ref(),
                location,
                &format!("resources.{resource}"),
            )?;
            Ok(Some(ProgramMount::Resource { path, resource }))
        }
        LoweredMountSource::Framework(capability) => {
            let path = ensure_concrete_non_file_mount(
                &path,
                when.as_ref(),
                each.as_ref(),
                location,
                &format!("framework.{capability}"),
            )?;
            Ok(Some(ProgramMount::Framework { path, capability }))
        }
    }
}

fn ensure_concrete_non_file_mount(
    path: &TemplateString,
    when: Option<&ProgramCondition>,
    each: Option<&ProgramEach>,
    location: &str,
    source: &str,
) -> Result<String, String> {
    if when.is_some() {
        return Err(format!(
            "{location} uses source `{source}` behind a runtime `when`, but only file mounts may \
             remain conditional after linking"
        ));
    }
    if each.is_some() {
        return Err(format!(
            "{location} uses source `{source}` behind a runtime `each`, but only file mounts may \
             remain repeated after linking"
        ));
    }
    if template_string_is_dynamic(path) {
        return Err(format!(
            "{location} uses source `{source}` with a non-concrete mount path, but storage and \
             framework mounts must resolve entirely during linking"
        ));
    }

    let path = render_template_string_static(path);
    if !path.starts_with('/') {
        return Err(format!(
            "{location}.path resolves to `{path}`, but non-file mount paths must be absolute"
        ));
    }
    if path.split('/').any(|segment| segment == "..") {
        return Err(format!(
            "{location}.path resolves to `{path}`, but non-file mount paths must not contain `..`"
        ));
    }

    Ok(path)
}

fn lower_template_string(
    component_id: ComponentId,
    location: &str,
    value: &InterpolatedString,
    component_config: &ComponentConfigAnalysis,
    item: ItemLowering<'_>,
) -> Result<TemplateString, String> {
    let mut out = Vec::new();
    for part in &value.parts {
        match part {
            InterpolatedPart::Literal(lit) => push_template_literal(&mut out, lit),
            InterpolatedPart::Interpolation { source, query } => match source {
                InterpolationSource::Config => {
                    match resolve_config_string(component_config, query)? {
                        Some(value) => push_template_literal(&mut out, &value),
                        None => out.push(TemplatePart::config(query.clone())),
                    }
                }
                InterpolationSource::Slots => {
                    out.push(TemplatePart::slot(component_id.0 as u64, query.clone()))
                }
                InterpolationSource::Item => match item {
                    ItemLowering::None => {
                        return Err(format!(
                            "`item` interpolation is only valid inside repeated mount expansions \
                             in {location}"
                        ));
                    }
                    ItemLowering::Static(item) => {
                        push_template_literal(
                            &mut out,
                            &resolve_item_interpolation(item, query, location, "template")?,
                        );
                    }
                    ItemLowering::CurrentItem => {
                        out.push(TemplatePart::current_item(query.clone()))
                    }
                },
                _ => unreachable!("unsupported interpolation source in mount template"),
            },
            _ => unreachable!("unsupported interpolation part in mount template"),
        }
    }
    Ok(out)
}

fn classify_mount_source(source: TemplateString) -> Result<LoweredMountSource, String> {
    if let Some(literal) = render_template_string_static_opt(&source) {
        return match literal.parse::<MountSource>() {
            Ok(MountSource::Config(path)) => {
                Ok(LoweredMountSource::File(FileMountSource::Config {
                    path: literal_template(path),
                }))
            }
            Ok(MountSource::Slot(slot)) => Ok(LoweredMountSource::Slot(slot)),
            Ok(MountSource::Resource(resource)) => Ok(LoweredMountSource::Resource(resource)),
            Ok(MountSource::Framework(capability)) => Ok(LoweredMountSource::Framework(capability)),
            Err(err) => Err(err.to_string()),
            Ok(_) => unreachable!("unsupported mount source kind"),
        };
    }

    if let Some(path) = strip_literal_prefix(&source, "config.") {
        return Ok(LoweredMountSource::File(FileMountSource::Config { path }));
    }
    Err(
        "mount source must resolve to a concrete `slots.*`, `resources.*`, or `framework.*` \
         reference, or remain a `config.*` file mount"
            .to_string(),
    )
}

fn resolve_config_string(
    component_config: &ComponentConfigAnalysis,
    query: &str,
) -> Result<Option<String>, String> {
    component_config.resolve_static_string_query(query)
}

fn resolve_item_interpolation(
    item: &Value,
    query: &str,
    location: &str,
    field: &str,
) -> Result<String, String> {
    let value = query_value(item, query).ok_or_else(|| {
        let label = if query.is_empty() {
            "item".to_string()
        } else {
            format!("item.{query}")
        };
        format!("failed to resolve {label} in {location}.{field}")
    })?;
    rc::stringify_for_interpolation(value).map_err(|err| err.to_string())
}

fn query_value<'a>(root: &'a Value, query: &str) -> Option<&'a Value> {
    if query.is_empty() {
        return Some(root);
    }
    let mut current = root;
    for segment in query.split('.') {
        match current {
            Value::Object(map) => current = map.get(segment)?,
            _ => return None,
        }
    }
    Some(current)
}

fn strip_literal_prefix(value: &[TemplatePart], prefix: &str) -> Option<TemplateString> {
    let mut remaining = prefix;
    let mut out = Vec::new();
    let mut stripped = false;

    for part in value {
        match part {
            TemplatePart::Lit { lit } if !stripped => {
                if remaining.is_empty() {
                    push_template_literal(&mut out, lit);
                    stripped = true;
                    continue;
                }

                if remaining.starts_with(lit.as_str()) {
                    remaining = &remaining[lit.len()..];
                    continue;
                }

                if let Some(suffix) = lit.strip_prefix(remaining) {
                    if !suffix.is_empty() {
                        push_template_literal(&mut out, suffix);
                    }
                    remaining = "";
                    stripped = true;
                    continue;
                }

                return None;
            }
            _ if !stripped => {
                if !remaining.is_empty() {
                    return None;
                }
                out.push(part.clone());
                stripped = true;
            }
            _ => out.push(part.clone()),
        }
    }

    remaining.is_empty().then_some(out)
}

fn template_string_is_dynamic(value: &[TemplatePart]) -> bool {
    value
        .iter()
        .any(|part| !matches!(part, TemplatePart::Lit { .. }))
}

fn render_template_string_static(value: &[TemplatePart]) -> String {
    let mut out = String::new();
    for part in value {
        let TemplatePart::Lit { lit } = part else {
            unreachable!("static template string cannot contain dynamic parts");
        };
        out.push_str(lit);
    }
    out
}

fn render_template_string_static_opt(value: &[TemplatePart]) -> Option<String> {
    (!template_string_is_dynamic(value)).then(|| render_template_string_static(value))
}

fn literal_template(value: impl Into<String>) -> TemplateString {
    let value = value.into();
    if value.is_empty() {
        Vec::new()
    } else {
        vec![TemplatePart::lit(value)]
    }
}

fn push_template_literal(out: &mut TemplateString, value: &str) {
    if value.is_empty() {
        return;
    }

    match out.last_mut() {
        Some(TemplatePart::Lit { lit }) => lit.push_str(value),
        _ => out.push(TemplatePart::lit(value)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use amber_config::ConfigNode;
    use amber_manifest::Manifest;
    use amber_scenario::{FileMountSource, ProgramMount};
    use amber_template::TemplatePart;

    use super::{
        ProgramLoweringSite, lower_program, lower_program_with_origins,
        lower_program_with_origins_and_root_schema, validate_lowered_program_mounts,
    };

    #[test]
    fn lower_program_expands_static_config_endpoints() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "app",
                entrypoint: ["app"],
                network: {
                  endpoints: [
                    {
                      each: "config.endpoints",
                      name: "${item.name}",
                      port: "${item.port}",
                    },
                  ],
                },
              },
              config_schema: {
                type: "object",
                properties: {
                  endpoints: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        name: { type: "string" },
                        port: { type: "integer" },
                      },
                      required: ["name", "port"],
                    },
                  },
                },
              },
            }
        "#
        .parse()
        .expect("manifest");
        let template = ConfigNode::Object(BTreeMap::from([(
            "endpoints".to_string(),
            ConfigNode::Array(vec![
                ConfigNode::Object(BTreeMap::from([
                    ("name".to_string(), ConfigNode::String("http".to_string())),
                    ("port".to_string(), ConfigNode::Number(8080.into())),
                ])),
                ConfigNode::Object(BTreeMap::from([
                    ("name".to_string(), ConfigNode::String("admin".to_string())),
                    ("port".to_string(), ConfigNode::Number(9090.into())),
                ])),
            ]),
        )]));

        let program = lower_program(
            amber_scenario::ComponentId(7),
            manifest.program().expect("program"),
            Some(&template),
        )
        .expect("program should lower");

        let endpoints = &program.network().expect("network").endpoints;
        assert_eq!(endpoints.len(), 2);
        assert_eq!(endpoints[0].name, "http");
        assert_eq!(endpoints[0].port, 8080);
        assert_eq!(endpoints[1].name, "admin");
        assert_eq!(endpoints[1].port, 9090);
    }

    #[test]
    fn lower_program_uses_root_schema_defaults_for_endpoint_when() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              config_schema: {
                type: "object",
                properties: {
                  enabled: {
                    type: "boolean",
                    default: false,
                  },
                },
              },
              program: {
                image: "app",
                entrypoint: ["app"],
                network: {
                  endpoints: [
                    {
                      name: "http",
                      port: 8080,
                      protocol: "http",
                      when: "config.enabled",
                    },
                  ],
                },
              },
            }
        "#
        .parse()
        .expect("manifest");

        let lowered = lower_program_with_origins_and_root_schema(
            amber_scenario::ComponentId(12),
            manifest.program().expect("program"),
            None,
            manifest.config_schema().map(|schema| &schema.0),
        )
        .expect("program should lower");

        let endpoints = &lowered.program.network().expect("network").endpoints;
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].name, "http");
    }

    #[test]
    fn lower_program_uses_root_schema_defaults_for_config_ref_leaf_endpoint_when() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "app",
                entrypoint: ["app"],
                network: {
                  endpoints: [
                    {
                      name: "http",
                      port: 8080,
                      protocol: "http",
                      when: "config.enabled",
                    },
                  ],
                },
              },
            }
        "#
        .parse()
        .expect("manifest");
        let template = ConfigNode::Object(BTreeMap::from([(
            "enabled".to_string(),
            ConfigNode::ConfigRef("root_enabled".to_string()),
        )]));
        let root_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "root_enabled": {
                    "type": "boolean",
                    "default": false
                }
            }
        });

        let lowered = lower_program_with_origins_and_root_schema(
            amber_scenario::ComponentId(12),
            manifest.program().expect("program"),
            Some(&template),
            Some(&root_schema),
        )
        .expect("program should lower");

        let endpoints = &lowered.program.network().expect("network").endpoints;
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].name, "http");
    }

    #[test]
    fn lower_program_keeps_nullable_ancestor_endpoint_when_runtime() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              config_schema: {
                type: "object",
                properties: {
                  settings: {
                    type: ["object", "null"],
                    properties: {
                      enabled: {
                        type: "boolean",
                        default: false,
                      },
                    },
                  },
                },
              },
              program: {
                image: "app",
                entrypoint: ["app"],
                network: {
                  endpoints: [
                    {
                      name: "http",
                      port: 8080,
                      protocol: "http",
                      when: "config.settings.enabled",
                    },
                  ],
                },
              },
            }
        "#
        .parse()
        .expect("manifest");

        let errors = lower_program_with_origins_and_root_schema(
            amber_scenario::ComponentId(12),
            manifest.program().expect("program"),
            None,
            manifest.config_schema().map(|schema| &schema.0),
        )
        .expect_err("endpoint should remain runtime-conditional");

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].site, ProgramLoweringSite::Endpoint(0));
        assert!(errors[0].message.contains(
            "depends on runtime config, but endpoints must resolve entirely at compile time"
        ));
    }

    #[test]
    fn lower_program_classifies_static_config_mount_sources() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "app",
                entrypoint: ["app"],
                mounts: [
                  {
                    path: "/data",
                    from: "resources.${config.resource_name}",
                  },
                  {
                    path: "/cfg",
                    from: "config.${config.mount_path}",
                  },
                ],
              },
              config_schema: {
                type: "object",
                properties: {
                  resource_name: { type: "string" },
                  mount_path: { type: "string" },
                },
              },
              resources: {
                data: { kind: "storage" },
              },
            }
        "#
        .parse()
        .expect("manifest");
        let template = ConfigNode::Object(BTreeMap::from([
            (
                "resource_name".to_string(),
                ConfigNode::String("data".to_string()),
            ),
            (
                "mount_path".to_string(),
                ConfigNode::String("app".to_string()),
            ),
        ]));

        let program = lower_program(
            amber_scenario::ComponentId(3),
            manifest.program().expect("program"),
            Some(&template),
        )
        .expect("program should lower");

        assert_eq!(
            program.mounts(),
            &[
                ProgramMount::Resource {
                    path: "/data".to_string(),
                    resource: "data".to_string(),
                },
                ProgramMount::File(amber_scenario::FileMount {
                    when: None,
                    each: None,
                    path: vec![TemplatePart::lit("/cfg")],
                    source: FileMountSource::Config {
                        path: vec![TemplatePart::lit("app")],
                    },
                }),
            ]
        );
    }

    #[test]
    fn lower_program_rejects_dynamic_mount_sources_outside_config_namespace() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "app",
                entrypoint: ["app"],
                mounts: [
                  {
                    path: "/cfg",
                    from: "secret.${config.mount_path}",
                  },
                ],
              },
              config_schema: {
                type: "object",
                properties: {
                  mount_path: { type: "string" },
                },
              },
            }
        "#
        .parse()
        .expect("manifest");
        let template = ConfigNode::Object(BTreeMap::from([(
            "mount_path".to_string(),
            ConfigNode::String("token".to_string()),
        )]));

        let errors = lower_program(
            amber_scenario::ComponentId(3),
            manifest.program().expect("program"),
            Some(&template),
        )
        .expect_err("program should fail to lower");

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].site, ProgramLoweringSite::Mount(0));
        assert!(errors[0].message.contains("unknown mount source"));
    }

    #[test]
    fn lower_program_rejects_runtime_non_file_mounts() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "app",
                entrypoint: ["app"],
                mounts: [
                  {
                    when: "config.enabled",
                    path: "/data",
                    from: "resources.data",
                  },
                ],
              },
              config_schema: {
                type: "object",
                properties: {
                  enabled: { type: "boolean" },
                },
              },
              resources: {
                data: { kind: "storage" },
              },
            }
        "#
        .parse()
        .expect("manifest");
        let template = ConfigNode::Object(BTreeMap::from([(
            "enabled".to_string(),
            ConfigNode::ConfigRef("enabled".to_string()),
        )]));

        let errors = lower_program(
            amber_scenario::ComponentId(3),
            manifest.program().expect("program"),
            Some(&template),
        )
        .expect_err("program should fail to lower");

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].site, ProgramLoweringSite::Mount(0));
        assert!(
            errors[0]
                .message
                .contains("only file mounts may remain conditional")
        );
    }

    #[test]
    fn lower_program_rejects_empty_endpoint_names() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "app",
                entrypoint: ["app"],
                network: {
                  endpoints: [
                    { name: "", port: 8080 },
                  ],
                },
              },
            }
        "#
        .parse()
        .expect("manifest");

        let errors = lower_program(
            amber_scenario::ComponentId(1),
            manifest.program().expect("program"),
            None,
        )
        .expect_err("empty endpoint names must be rejected");

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].site, ProgramLoweringSite::Endpoint(0));
        assert!(
            errors[0]
                .message
                .contains("program.network.endpoints[0].name resolves to an empty string")
        );
    }

    #[test]
    fn lower_program_rejects_relative_non_file_mount_paths_after_expansion() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "app",
                entrypoint: ["app"],
                mounts: [
                  {
                    path: "${config.mount_path}",
                    from: "resources.data",
                  },
                ],
              },
              config_schema: {
                type: "object",
                properties: {
                  mount_path: { type: "string" },
                },
              },
              resources: {
                data: { kind: "storage" },
              },
            }
        "#
        .parse()
        .expect("manifest");
        let template = ConfigNode::Object(BTreeMap::from([(
            "mount_path".to_string(),
            ConfigNode::String("relative/path".to_string()),
        )]));

        let errors = lower_program(
            amber_scenario::ComponentId(3),
            manifest.program().expect("program"),
            Some(&template),
        )
        .expect_err("relative concrete storage mount paths must be rejected");

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].site, ProgramLoweringSite::Mount(0));
        assert!(
            errors[0]
                .message
                .contains("non-file mount paths must be absolute")
        );
    }

    #[test]
    fn lower_program_preserves_authored_mount_indices_for_expanded_mounts() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "app",
                entrypoint: ["app"],
                mounts: [
                  {
                    each: "config.mounts",
                    path: "/${item}",
                    from: "resources.${item}",
                  },
                ],
              },
              config_schema: {
                type: "object",
                properties: {
                  mounts: {
                    type: "array",
                    items: { type: "string" },
                  },
                },
              },
            }
        "#
        .parse()
        .expect("manifest");
        let template = ConfigNode::Object(BTreeMap::from([(
            "mounts".to_string(),
            ConfigNode::Array(vec![
                ConfigNode::String("alpha".to_string()),
                ConfigNode::String("beta".to_string()),
            ]),
        )]));

        let lowered = lower_program_with_origins(
            amber_scenario::ComponentId(9),
            manifest.program().expect("program"),
            Some(&template),
        )
        .expect("program should lower");

        assert_eq!(lowered.program.mounts().len(), 2);
        assert_eq!(lowered.mount_source_indices, vec![0, 0]);
    }

    #[test]
    fn validate_lowered_program_mounts_rejects_duplicate_paths_after_static_expansion() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              program: {
                image: "app",
                entrypoint: ["app"],
                mounts: [
                  {
                    each: "config.mounts",
                    path: "/${item}",
                    from: "resources.state",
                  },
                ],
              },
              config_schema: {
                type: "object",
                properties: {
                  mounts: {
                    type: "array",
                    items: { type: "string" },
                  },
                },
              },
              resources: {
                state: { kind: "storage" },
              },
            }
        "#
        .parse()
        .expect("manifest");
        let template = ConfigNode::Object(BTreeMap::from([(
            "mounts".to_string(),
            ConfigNode::Array(vec![
                ConfigNode::String("same".to_string()),
                ConfigNode::String("same".to_string()),
            ]),
        )]));

        let lowered = lower_program_with_origins(
            amber_scenario::ComponentId(10),
            manifest.program().expect("program"),
            Some(&template),
        )
        .expect("program should lower");
        let errors = validate_lowered_program_mounts(
            &lowered.program,
            &lowered.mount_source_indices,
            manifest.config_schema(),
            manifest.resources(),
            manifest.slots(),
            manifest.experimental_features(),
        )
        .expect_err("duplicate concrete mount paths must be rejected");

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].site, ProgramLoweringSite::Mount(0));
        assert!(
            errors[0]
                .message
                .contains("duplicate mount path `/same` after mount expansion")
        );
    }

    #[test]
    fn validate_lowered_program_mounts_rejects_dynamic_file_mounts_without_config_schema() {
        let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              slots: {
                api: { kind: "http" },
              },
              program: {
                image: "app",
                entrypoint: ["app"],
                mounts: [
                  {
                    path: "/tmp/value",
                    from: "config.${slots.api.url}",
                  },
                ],
              },
            }
        "#
        .parse()
        .expect("manifest");

        let lowered = lower_program_with_origins(
            amber_scenario::ComponentId(11),
            manifest.program().expect("program"),
            None,
        )
        .expect("program should lower");
        let errors = validate_lowered_program_mounts(
            &lowered.program,
            &lowered.mount_source_indices,
            manifest.config_schema(),
            manifest.resources(),
            manifest.slots(),
            manifest.experimental_features(),
        )
        .expect_err("dynamic file mounts without config_schema must be rejected");

        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].site, ProgramLoweringSite::Mount(0));
        assert!(
            errors[0]
                .message
                .contains("requires `config_schema`, but the component does not declare one")
        );
    }
}
