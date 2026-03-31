use super::*;

pub(crate) fn build_mount_specs(
    scenario: &Scenario,
    config_analysis: &ScenarioConfigAnalysis,
    program_components: &[ComponentId],
    runtime_address_resolution: RuntimeAddressResolution,
    slot_values_by_component: &HashMap<ComponentId, BTreeMap<String, SlotValue>>,
) -> Result<HashMap<ComponentId, Vec<MountSpec>>, MeshError> {
    let mut out = HashMap::new();

    for id in program_components {
        let component = scenario.component(*id);
        let program = component
            .program
            .as_ref()
            .expect("program component has program");
        if program.mounts().is_empty() {
            continue;
        }

        let slots = slot_values_by_component.get(id).ok_or_else(|| {
            MeshError::new(format!(
                "internal error: missing slot values for {}",
                component_label(scenario, *id)
            ))
        })?;
        let needs_component_config = program.mounts().iter().any(|mount| {
            matches!(mount, ProgramMount::File(file_mount) if file_mount_uses_config(file_mount))
        });

        if needs_component_config && component.config_schema.is_none() {
            return Err(MeshError::new(format!(
                "component {} requires config_schema when using program.mounts",
                component_label(scenario, *id)
            )));
        }

        let component_config = config_analysis.component(*id).ok_or_else(|| {
            MeshError::new(format!(
                "no config analysis for component {}",
                component_label(scenario, *id)
            ))
        })?;

        let mut specs = Vec::new();
        for (mount_idx, mount) in program.mounts().iter().enumerate() {
            let ProgramMount::File(mount) = mount else {
                continue;
            };

            let when = resolve_file_mount_when(mount.when.as_ref(), component_config, slots)?;
            if matches!(when, ResolvedWhen::Absent) {
                continue;
            }
            let runtime_when = match &when {
                ResolvedWhen::Runtime(query) => Some(query.clone()),
                ResolvedWhen::Present | ResolvedWhen::Absent => None,
            };
            let location = format!("program.mounts[{mount_idx}]");

            let emit_spec = |item_resolution,
                             runtime_each: Option<RepeatedTemplateSource>,
                             specs: &mut Vec<MountSpec>|
             -> Result<(), MeshError> {
                let mut needs_helper_for_mount = false;
                let mut needs_runtime_config_for_mount = false;
                let path_ts = resolve_lowered_template_string(
                    scenario,
                    *id,
                    &format!("{location}.path"),
                    runtime_address_resolution,
                    &mount.path,
                    slots,
                    component_config,
                    item_resolution,
                    &mut needs_helper_for_mount,
                    &mut needs_runtime_config_for_mount,
                    true,
                )?;
                let source_ts = resolve_lowered_mount_source(
                    scenario,
                    *id,
                    &format!("{location}.from"),
                    runtime_address_resolution,
                    &mount.source,
                    slots,
                    component_config,
                    item_resolution,
                    &mut needs_helper_for_mount,
                    &mut needs_runtime_config_for_mount,
                    true,
                )?;

                if runtime_when.is_some()
                    || runtime_each.is_some()
                    || needs_helper_for_mount
                    || needs_runtime_config_for_mount
                {
                    specs.push(MountSpec::Template(MountTemplateSpec {
                        when: runtime_when.clone(),
                        each: runtime_each,
                        path: path_ts,
                        source: source_ts,
                    }));
                    return Ok(());
                }

                let path = render_template_string_static(&path_ts)?;
                let source_raw = render_template_string_static(&source_ts)?;
                let source = rc::parse_rendered_file_mount_source(&source_raw).map_err(|err| {
                    MeshError::new(format!(
                        "invalid mount source `{source_raw}` in {} {location}: {err}",
                        component_label(scenario, *id)
                    ))
                })?;
                let component_schema = component_config
                    .component_schema()
                    .expect("file mounts require config_schema");
                rc::validate_rendered_file_mount_source(component_schema, source).map_err(
                    |err| {
                        MeshError::new(format!(
                            "invalid mount source `{source_raw}` in {} {location}: {err}",
                            component_label(scenario, *id)
                        ))
                    },
                )?;
                let path_query = source.path();
                match resolve_config_query_for_mount(component_config, path_query)? {
                    MountResolution::Static(value) => {
                        let content = rc::stringify_for_mount(&value)
                            .map_err(|err| MeshError::new(err.to_string()))?;
                        specs.push(MountSpec::Literal { path, content });
                    }
                    MountResolution::Runtime => {
                        specs.push(MountSpec::Template(MountTemplateSpec {
                            when: runtime_when.clone(),
                            each: runtime_each,
                            path: path_ts,
                            source: source_ts,
                        }));
                    }
                }
                Ok(())
            };

            match mount.each.as_ref() {
                None => emit_spec(ItemResolution::NotAllowed, None, &mut specs)?,
                Some(each) => match each {
                    ProgramEach::Slot { slot: slot_name } => {
                        let scope = id.0 as u64;
                        let items = repeated_slot_items_for_component(
                            scenario, *id, slot_name, slots, &location,
                        )?;
                        for (item_idx, item) in items.iter().enumerate() {
                            let item_resolution = if matches!(
                                runtime_address_resolution,
                                RuntimeAddressResolution::Deferred
                            ) {
                                ItemResolution::RuntimeSlotTemplate {
                                    scope,
                                    slot: slot_name,
                                    index: item_idx,
                                    item,
                                }
                            } else {
                                ItemResolution::StaticSlot(item)
                            };
                            emit_spec(item_resolution, None, &mut specs)?;
                        }
                    }
                    ProgramEach::Config { path } => {
                        match resolve_config_each_values(component_config, path, &location)? {
                            ConfigEachResolution::Static(items) => {
                                for item in &items {
                                    emit_spec(
                                        ItemResolution::StaticConfig(item),
                                        None,
                                        &mut specs,
                                    )?;
                                }
                            }
                            ConfigEachResolution::Runtime => {
                                emit_spec(
                                    ItemResolution::RuntimeCurrentItem,
                                    Some(RepeatedTemplateSource::Config { path: path.clone() }),
                                    &mut specs,
                                )?;
                            }
                        }
                    }
                },
            }
        }

        if !specs.is_empty() {
            out.insert(*id, specs);
        }
    }

    Ok(out)
}

pub(super) fn resolve_file_mount_when(
    when: Option<&ProgramCondition>,
    component_config: &ComponentConfigAnalysis,
    slots: &BTreeMap<String, SlotValue>,
) -> Result<ResolvedWhen, MeshError> {
    let Some(when) = when else {
        return Ok(ResolvedWhen::Present);
    };

    match when {
        ProgramCondition::Config { path } => {
            match resolve_condition_presence_for_program(
                InterpolationSource::Config,
                path,
                component_config,
                slots,
            )? {
                ConfigPresence::Present => Ok(ResolvedWhen::Present),
                ConfigPresence::Absent => Ok(ResolvedWhen::Absent),
                ConfigPresence::Runtime => Ok(ResolvedWhen::Runtime(path.clone())),
            }
        }
        ProgramCondition::Slot { query } => {
            match resolve_condition_presence_for_program(
                InterpolationSource::Slots,
                query,
                component_config,
                slots,
            )? {
                ConfigPresence::Present => Ok(ResolvedWhen::Present),
                ConfigPresence::Absent => Ok(ResolvedWhen::Absent),
                ConfigPresence::Runtime => {
                    unreachable!("slot conditions always resolve before runtime")
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_lowered_template_string(
    scenario: &Scenario,
    id: ComponentId,
    location: &str,
    runtime_address_resolution: RuntimeAddressResolution,
    value: &TemplateString,
    slots: &BTreeMap<String, SlotValue>,
    component_config: &ComponentConfigAnalysis,
    item_resolution: ItemResolution<'_>,
    needs_helper_for_program_templates: &mut bool,
    needs_runtime_config_for_program_templates: &mut bool,
    require_non_empty: bool,
) -> Result<TemplateString, MeshError> {
    let component = component_label(scenario, id);
    let mut ts: TemplateString = Vec::new();
    for part in value {
        match part {
            TemplatePart::Lit { lit } => ts.push(TemplatePart::lit(lit)),
            TemplatePart::Config { config } => {
                match resolve_config_query_for_program(component_config, config)? {
                    ConfigResolution::Static(value) => ts.push(TemplatePart::lit(value)),
                    ConfigResolution::Runtime => {
                        ts.push(TemplatePart::config(config.clone()));
                        *needs_helper_for_program_templates = true;
                        *needs_runtime_config_for_program_templates = true;
                    }
                }
            }
            TemplatePart::Slot { slot, .. }
                if matches!(
                    runtime_address_resolution,
                    RuntimeAddressResolution::Deferred
                ) =>
            {
                resolve_slot_interpolation(
                    scenario,
                    id,
                    location,
                    &InterpolationSource::Slots,
                    slot,
                    slots,
                )?;
                ts.push(part.clone());
                *needs_helper_for_program_templates = true;
            }
            TemplatePart::Slot { slot, .. } => {
                if let Some(value) = resolve_slot_interpolation(
                    scenario,
                    id,
                    location,
                    &InterpolationSource::Slots,
                    slot,
                    slots,
                )? {
                    ts.push(TemplatePart::lit(value));
                }
            }
            TemplatePart::CurrentItem { item } => match item_resolution {
                ItemResolution::NotAllowed => {
                    return Err(MeshError::new(format!(
                        "`item` interpolation is only valid inside repeated `each` expansions in \
                         {component} {location}",
                    )));
                }
                ItemResolution::RuntimeSlotTemplate {
                    scope,
                    slot,
                    index,
                    item: item_value,
                } => {
                    resolve_slot_item_interpolation(item_value, item, &component, location)?;
                    ts.push(TemplatePart::item(scope, slot, index, item.clone()));
                    *needs_helper_for_program_templates = true;
                }
                ItemResolution::RuntimeCurrentItem => {
                    ts.push(TemplatePart::current_item(item.clone()));
                    *needs_helper_for_program_templates = true;
                }
                ItemResolution::StaticSlot(item_value) => ts.push(TemplatePart::lit(
                    resolve_slot_item_interpolation(item_value, item, &component, location)?,
                )),
                ItemResolution::StaticConfig(item_value) => ts.push(TemplatePart::lit(
                    resolve_item_interpolation_from_value(item_value, item, &component, location)?,
                )),
            },
            TemplatePart::Item { item, .. } => match item_resolution {
                ItemResolution::NotAllowed => {
                    return Err(MeshError::new(format!(
                        "`item` interpolation is only valid inside repeated `each` expansions in \
                         {component} {location}",
                    )));
                }
                ItemResolution::RuntimeSlotTemplate {
                    scope,
                    slot,
                    index,
                    item: item_value,
                } => {
                    resolve_slot_item_interpolation(item_value, item, &component, location)?;
                    ts.push(TemplatePart::item(scope, slot, index, item.clone()));
                    *needs_helper_for_program_templates = true;
                }
                ItemResolution::RuntimeCurrentItem => {
                    ts.push(TemplatePart::current_item(item.clone()));
                    *needs_helper_for_program_templates = true;
                }
                ItemResolution::StaticSlot(item_value) => ts.push(TemplatePart::lit(
                    resolve_slot_item_interpolation(item_value, item, &component, location)?,
                )),
                ItemResolution::StaticConfig(item_value) => ts.push(TemplatePart::lit(
                    resolve_item_interpolation_from_value(item_value, item, &component, location)?,
                )),
            },
        }
    }
    if require_non_empty && ts.is_empty() {
        return Err(MeshError::new(format!(
            "internal error: produced empty template for {component} {location}",
        )));
    }
    Ok(ts)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_lowered_mount_source(
    scenario: &Scenario,
    id: ComponentId,
    location: &str,
    runtime_address_resolution: RuntimeAddressResolution,
    source: &FileMountSource,
    slots: &BTreeMap<String, SlotValue>,
    component_config: &ComponentConfigAnalysis,
    item_resolution: ItemResolution<'_>,
    needs_helper_for_program_templates: &mut bool,
    needs_runtime_config_for_program_templates: &mut bool,
    require_non_empty: bool,
) -> Result<TemplateString, MeshError> {
    let FileMountSource::Config { path } = source;
    let path = resolve_lowered_template_string(
        scenario,
        id,
        location,
        runtime_address_resolution,
        path,
        slots,
        component_config,
        item_resolution,
        needs_helper_for_program_templates,
        needs_runtime_config_for_program_templates,
        false,
    )?;

    let mut full = Vec::new();
    if path.is_empty() {
        full.push(TemplatePart::lit("config"));
    } else {
        full.push(TemplatePart::lit("config."));
        full.extend(path);
    }
    if require_non_empty && full.is_empty() {
        return Err(MeshError::new(format!(
            "internal error: produced empty mount source for {} {location}",
            component_label(scenario, id)
        )));
    }
    Ok(full)
}
