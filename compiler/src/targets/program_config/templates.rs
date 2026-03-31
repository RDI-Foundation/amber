use super::*;

#[derive(Clone, Copy)]
pub(super) enum ItemResolution<'a> {
    NotAllowed,
    RuntimeSlotTemplate {
        scope: u64,
        slot: &'a str,
        index: usize,
        item: &'a SlotObject,
    },
    RuntimeCurrentItem,
    StaticSlot(&'a SlotObject),
    StaticConfig(&'a Value),
}

fn repeated_slot_items<'a>(slots: &'a BTreeMap<String, SlotValue>, slot: &str) -> &'a [SlotObject] {
    match slots.get(slot) {
        Some(SlotValue::One(value)) => std::slice::from_ref(value),
        Some(SlotValue::Many(values)) => values.as_slice(),
        None => &[],
    }
}

pub(super) fn repeated_slot_items_for_component<'a>(
    scenario: &'a Scenario,
    id: ComponentId,
    slot: &str,
    slots: &'a BTreeMap<String, SlotValue>,
    location: &str,
) -> Result<&'a [SlotObject], MeshError> {
    let component = component_label(scenario, id);
    let slot_decl = scenario.component(id).slots.get(slot).ok_or_else(|| {
        MeshError::new(format!("unknown slot `{slot}` in {component} {location}"))
    })?;
    if !slot_decl.multiple {
        return Err(MeshError::new(format!(
            "slot `{slot}` in {component} {location} is not declared with `multiple: true`"
        )));
    }
    Ok(repeated_slot_items(slots, slot))
}

fn query_value_opt<'a>(root: &'a Value, query: &str) -> Option<&'a Value> {
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

pub(super) fn resolve_item_interpolation_from_value(
    item: &Value,
    query: &str,
    component: &str,
    location: &str,
) -> Result<String, MeshError> {
    let value = query_value_opt(item, query).ok_or_else(|| {
        let label = if query.is_empty() {
            "item".to_string()
        } else {
            format!("item.{query}")
        };
        MeshError::new(format!(
            "failed to resolve {label} in {component} {location}"
        ))
    })?;
    rc::stringify_for_interpolation(value).map_err(|err| {
        MeshError::new(format!(
            "failed to stringify repeated slot item in {component} {location}: {err}"
        ))
    })
}

pub(super) fn resolve_slot_item_interpolation(
    item: &SlotObject,
    query: &str,
    component: &str,
    location: &str,
) -> Result<String, MeshError> {
    let value = serde_json::to_value(item).map_err(|err| {
        MeshError::new(format!(
            "failed to serialize repeated slot item in {component} {location}: {err}"
        ))
    })?;
    resolve_item_interpolation_from_value(&value, query, component, location)
}

pub(super) fn join_template_strings(
    values: Vec<TemplateString>,
    separator: &str,
) -> TemplateString {
    let mut out = Vec::new();
    for (idx, mut value) in values.into_iter().enumerate() {
        if idx > 0 && !separator.is_empty() {
            out.push(TemplatePart::lit(separator));
        }
        out.append(&mut value);
    }
    out
}

pub(crate) fn resolve_slot_interpolation(
    scenario: &Scenario,
    id: ComponentId,
    location: &str,
    source: &InterpolationSource,
    query: &str,
    slots: &BTreeMap<String, SlotValue>,
) -> Result<Option<String>, MeshError> {
    let component = component_label(scenario, id);
    match source {
        InterpolationSource::Slots => {
            let parsed = parse_slot_query(query).map_err(|err| {
                let label = if query.is_empty() {
                    "slots".to_string()
                } else {
                    format!("slots.{query}")
                };
                MeshError::new(format!(
                    "failed to resolve slot query in {component}: invalid slots interpolation \
                     `{label}`: {err}"
                ))
            })?;

            match parsed.target {
                SlotTarget::All => {
                    if scenario
                        .component(id)
                        .slots
                        .values()
                        .any(|slot| slot.multiple)
                    {
                        return Err(MeshError::new(format!(
                            "failed to resolve slot query in {component}: `${{slots}}` is not \
                             valid when the component declares any `multiple: true` slots"
                        )));
                    }
                }
                SlotTarget::Slot(slot_name) => {
                    if scenario
                        .component(id)
                        .slots
                        .get(slot_name)
                        .is_some_and(|slot| slot.multiple)
                    {
                        return Err(MeshError::new(format!(
                            "failed to resolve slot query in {component}: slot `{slot_name}` is \
                             declared with `multiple: true`; use `each: \"slots.{slot_name}\"` \
                             and `${{item...}}`"
                        )));
                    }
                }
            }

            resolve_slot_query(slots, query).map(Some).map_err(|e| {
                MeshError::new(format!("failed to resolve slot query in {component}: {e}"))
            })
        }
        InterpolationSource::Config => Ok(None),
        InterpolationSource::Item => Err(MeshError::new(format!(
            "`item` interpolation is only valid inside repeated `each` expansions in {component} \
             {location}",
        ))),
        other => Err(MeshError::new(format!(
            "unsupported interpolation source {other} in {component} {location}",
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn resolve_program_template_string(
    scenario: &Scenario,
    id: ComponentId,
    location: &str,
    value: &amber_manifest::InterpolatedString,
    runtime_address_resolution: RuntimeAddressResolution,
    slots: &BTreeMap<String, SlotValue>,
    component_config: &ComponentConfigAnalysis,
    item_resolution: ItemResolution<'_>,
    needs_helper_for_program_templates: &mut bool,
    needs_runtime_config_for_program_templates: &mut bool,
    require_non_empty: bool,
) -> Result<TemplateString, MeshError> {
    let component = component_label(scenario, id);
    let mut ts: TemplateString = Vec::new();
    for part in &value.parts {
        match part {
            InterpolatedPart::Literal(lit) => ts.push(TemplatePart::lit(lit)),
            InterpolatedPart::Interpolation { source, query } => {
                if *source == InterpolationSource::Item {
                    match item_resolution {
                        ItemResolution::NotAllowed => {
                            return Err(MeshError::new(format!(
                                "`item` interpolation is only valid inside repeated `each` \
                                 expansions in {component} {location}",
                            )));
                        }
                        ItemResolution::RuntimeSlotTemplate {
                            scope,
                            slot,
                            index,
                            item,
                        } => {
                            resolve_slot_item_interpolation(item, query, &component, location)?;
                            ts.push(TemplatePart::item(scope, slot, index, query.clone()));
                            *needs_helper_for_program_templates = true;
                        }
                        ItemResolution::RuntimeCurrentItem => {
                            ts.push(TemplatePart::current_item(query.clone()));
                            *needs_helper_for_program_templates = true;
                        }
                        ItemResolution::StaticSlot(item) => {
                            ts.push(TemplatePart::lit(resolve_slot_item_interpolation(
                                item, query, &component, location,
                            )?));
                        }
                        ItemResolution::StaticConfig(item) => {
                            ts.push(TemplatePart::lit(resolve_item_interpolation_from_value(
                                item, query, &component, location,
                            )?));
                        }
                    }
                    continue;
                }
                match source {
                    InterpolationSource::Slots
                        if matches!(
                            runtime_address_resolution,
                            RuntimeAddressResolution::Deferred
                        ) =>
                    {
                        ts.push(TemplatePart::slot(id.0 as u64, query.clone()));
                        *needs_helper_for_program_templates = true;
                        continue;
                    }
                    _ => {}
                }
                if let Some(value) =
                    resolve_slot_interpolation(scenario, id, location, source, query, slots)?
                {
                    ts.push(TemplatePart::lit(value));
                    continue;
                }
                match resolve_config_query_for_program(component_config, query)? {
                    ConfigResolution::Static(value) => ts.push(TemplatePart::lit(value)),
                    ConfigResolution::Runtime => {
                        ts.push(TemplatePart::config(query.clone()));
                        *needs_helper_for_program_templates = true;
                        *needs_runtime_config_for_program_templates = true;
                    }
                }
            }
            _ => {
                return Err(MeshError::new(format!(
                    "unsupported interpolation part in {component} {location}",
                )));
            }
        }
    }
    if require_non_empty && ts.is_empty() {
        return Err(MeshError::new(format!(
            "internal error: produced empty template for {component} {location}",
        )));
    }
    Ok(ts)
}

#[derive(Clone, Debug)]
pub(super) enum ResolvedWhen {
    Present,
    Absent,
    Runtime(String),
}

pub(super) fn resolve_program_when(
    when: Option<&amber_manifest::WhenPath>,
    component_config: &ComponentConfigAnalysis,
    slots: &BTreeMap<String, SlotValue>,
) -> Result<ResolvedWhen, MeshError> {
    let Some(when) = when else {
        return Ok(ResolvedWhen::Present);
    };

    match resolve_condition_presence_for_program(
        when.source(),
        when.query(),
        component_config,
        slots,
    )? {
        ConfigPresence::Present => Ok(ResolvedWhen::Present),
        ConfigPresence::Absent => Ok(ResolvedWhen::Absent),
        ConfigPresence::Runtime => {
            if when.source() != InterpolationSource::Config {
                return Err(MeshError::new(format!(
                    "internal error: runtime program `when` must be config-based, got `{when}`"
                )));
            }
            Ok(ResolvedWhen::Runtime(when.query().to_string()))
        }
    }
}

fn emit_program_arg_templates(
    out: &mut Vec<ProgramArgTemplate>,
    argv: Vec<TemplateString>,
    runtime_when: Option<String>,
    needs_helper_for_program_templates: &mut bool,
    needs_runtime_config_for_program_templates: &mut bool,
) {
    if argv.is_empty() {
        return;
    }

    if let Some(when) = runtime_when {
        *needs_helper_for_program_templates = true;
        *needs_runtime_config_for_program_templates = true;
        out.push(ProgramArgTemplate::Conditional(
            ConditionalProgramArgTemplate { when, argv },
        ));
        return;
    }

    out.extend(argv.into_iter().map(ProgramArgTemplate::Arg));
}

#[allow(clippy::too_many_arguments)]
pub(super) fn append_program_command_item_templates(
    scenario: &Scenario,
    id: ComponentId,
    location_prefix: &str,
    idx: usize,
    item: &ProgramArgItem,
    runtime_address_resolution: RuntimeAddressResolution,
    slots: &BTreeMap<String, SlotValue>,
    component_config: &ComponentConfigAnalysis,
    needs_helper_for_program_templates: &mut bool,
    needs_runtime_config_for_program_templates: &mut bool,
    out: &mut Vec<ProgramArgTemplate>,
) -> Result<(), MeshError> {
    let when = resolve_program_when(item.when(), component_config, slots)?;
    if matches!(when, ResolvedWhen::Absent) {
        return Ok(());
    }

    let runtime_when = match &when {
        ResolvedWhen::Runtime(query) => Some(query.clone()),
        ResolvedWhen::Present | ResolvedWhen::Absent => None,
    };

    let location = format!("{location_prefix}[{idx}]");
    let render_arg = |location: &str,
                      value: &amber_manifest::InterpolatedString,
                      item_resolution,
                      needs_helper_for_program_templates: &mut bool,
                      needs_runtime_config_for_program_templates: &mut bool|
     -> Result<TemplateString, MeshError> {
        resolve_program_template_string(
            scenario,
            id,
            location,
            value,
            runtime_address_resolution,
            slots,
            component_config,
            item_resolution,
            needs_helper_for_program_templates,
            needs_runtime_config_for_program_templates,
            true,
        )
    };

    match item.each() {
        None => {
            let mut argv = Vec::new();
            match &item.value {
                amber_manifest::ProgramArgValue::Arg(arg) => {
                    argv.push(render_arg(
                        &location,
                        arg,
                        ItemResolution::NotAllowed,
                        needs_helper_for_program_templates,
                        needs_runtime_config_for_program_templates,
                    )?);
                }
                amber_manifest::ProgramArgValue::Argv(args) => {
                    for (group_idx, arg) in args.iter().enumerate() {
                        argv.push(render_arg(
                            &format!("{location}.argv[{group_idx}]"),
                            arg,
                            ItemResolution::NotAllowed,
                            needs_helper_for_program_templates,
                            needs_runtime_config_for_program_templates,
                        )?);
                    }
                }
            }
            emit_program_arg_templates(
                out,
                argv,
                runtime_when,
                needs_helper_for_program_templates,
                needs_runtime_config_for_program_templates,
            );
            Ok(())
        }
        Some(each) => match each.source() {
            InterpolationSource::Slots => {
                let scope = id.0 as u64;
                let slot_name = each
                    .slot()
                    .expect("slot-based each path should expose a slot name");
                let items =
                    repeated_slot_items_for_component(scenario, id, slot_name, slots, &location)?;
                if items.is_empty() {
                    return Ok(());
                }

                let item_resolution = |item_idx, item| {
                    if matches!(
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
                    }
                };

                let mut argv = Vec::new();
                match &item.value {
                    amber_manifest::ProgramArgValue::Arg(arg) => {
                        let arg_location = format!("{location}.arg");
                        if let Some(join) = item.join() {
                            let mut rendered = Vec::with_capacity(items.len());
                            for (item_idx, repeated_item) in items.iter().enumerate() {
                                rendered.push(render_arg(
                                    &arg_location,
                                    arg,
                                    item_resolution(item_idx, repeated_item),
                                    needs_helper_for_program_templates,
                                    needs_runtime_config_for_program_templates,
                                )?);
                            }
                            argv.push(join_template_strings(rendered, join));
                        } else {
                            for (item_idx, repeated_item) in items.iter().enumerate() {
                                argv.push(render_arg(
                                    &arg_location,
                                    arg,
                                    item_resolution(item_idx, repeated_item),
                                    needs_helper_for_program_templates,
                                    needs_runtime_config_for_program_templates,
                                )?);
                            }
                        }
                    }
                    amber_manifest::ProgramArgValue::Argv(args) => {
                        for (item_idx, repeated_item) in items.iter().enumerate() {
                            for (group_idx, arg) in args.iter().enumerate() {
                                argv.push(render_arg(
                                    &format!("{location}.argv[{group_idx}]"),
                                    arg,
                                    item_resolution(item_idx, repeated_item),
                                    needs_helper_for_program_templates,
                                    needs_runtime_config_for_program_templates,
                                )?);
                            }
                        }
                    }
                }

                emit_program_arg_templates(
                    out,
                    argv,
                    runtime_when,
                    needs_helper_for_program_templates,
                    needs_runtime_config_for_program_templates,
                );
                Ok(())
            }
            InterpolationSource::Config => {
                match resolve_config_each_values(component_config, each.query(), &location)? {
                    ConfigEachResolution::Static(items) => {
                        if items.is_empty() {
                            return Ok(());
                        }

                        let mut argv = Vec::new();
                        match &item.value {
                            amber_manifest::ProgramArgValue::Arg(arg) => {
                                let arg_location = format!("{location}.arg");
                                if let Some(join) = item.join() {
                                    let mut rendered = Vec::with_capacity(items.len());
                                    for repeated_item in &items {
                                        rendered.push(render_arg(
                                            &arg_location,
                                            arg,
                                            ItemResolution::StaticConfig(repeated_item),
                                            needs_helper_for_program_templates,
                                            needs_runtime_config_for_program_templates,
                                        )?);
                                    }
                                    argv.push(join_template_strings(rendered, join));
                                } else {
                                    for repeated_item in &items {
                                        argv.push(render_arg(
                                            &arg_location,
                                            arg,
                                            ItemResolution::StaticConfig(repeated_item),
                                            needs_helper_for_program_templates,
                                            needs_runtime_config_for_program_templates,
                                        )?);
                                    }
                                }
                            }
                            amber_manifest::ProgramArgValue::Argv(args) => {
                                for repeated_item in &items {
                                    for (group_idx, arg) in args.iter().enumerate() {
                                        argv.push(render_arg(
                                            &format!("{location}.argv[{group_idx}]"),
                                            arg,
                                            ItemResolution::StaticConfig(repeated_item),
                                            needs_helper_for_program_templates,
                                            needs_runtime_config_for_program_templates,
                                        )?);
                                    }
                                }
                            }
                        }

                        emit_program_arg_templates(
                            out,
                            argv,
                            runtime_when,
                            needs_helper_for_program_templates,
                            needs_runtime_config_for_program_templates,
                        );
                        Ok(())
                    }
                    ConfigEachResolution::Runtime => {
                        *needs_helper_for_program_templates = true;
                        *needs_runtime_config_for_program_templates = true;

                        let repeated = match &item.value {
                            amber_manifest::ProgramArgValue::Arg(arg) => {
                                RepeatedProgramArgTemplate {
                                    when: runtime_when,
                                    each: RepeatedTemplateSource::Config {
                                        path: each.query().to_string(),
                                    },
                                    arg: Some(render_arg(
                                        &format!("{location}.arg"),
                                        arg,
                                        ItemResolution::RuntimeCurrentItem,
                                        needs_helper_for_program_templates,
                                        needs_runtime_config_for_program_templates,
                                    )?),
                                    argv: Vec::new(),
                                    join: item.join().map(ToString::to_string),
                                }
                            }
                            amber_manifest::ProgramArgValue::Argv(args) => {
                                let mut argv = Vec::with_capacity(args.0.len());
                                for (group_idx, arg) in args.iter().enumerate() {
                                    argv.push(render_arg(
                                        &format!("{location}.argv[{group_idx}]"),
                                        arg,
                                        ItemResolution::RuntimeCurrentItem,
                                        needs_helper_for_program_templates,
                                        needs_runtime_config_for_program_templates,
                                    )?);
                                }
                                RepeatedProgramArgTemplate {
                                    when: runtime_when,
                                    each: RepeatedTemplateSource::Config {
                                        path: each.query().to_string(),
                                    },
                                    arg: None,
                                    argv,
                                    join: None,
                                }
                            }
                        };

                        out.push(ProgramArgTemplate::Repeated(repeated));
                        Ok(())
                    }
                }
            }
            InterpolationSource::Item => {
                unreachable!("each paths never use item as a source")
            }
            _ => unreachable!("unsupported interpolation source for each"),
        },
    }
}
