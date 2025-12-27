use std::{collections::BTreeSet, fmt};

use crate::{
    BindingSource, BindingTarget, ExportTarget, InterpolatedPart, InterpolatedString,
    InterpolationSource, Manifest, SlotName,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LintCode {
    UnusedProgram,
    UnusedSlot,
    UnusedProvide,
    DuplicateEnvironmentResolver,
}

impl LintCode {
    pub fn as_str(self) -> &'static str {
        match self {
            LintCode::UnusedProgram => "manifest::unused-program",
            LintCode::UnusedSlot => "manifest::unused-slot",
            LintCode::UnusedProvide => "manifest::unused-provide",
            LintCode::DuplicateEnvironmentResolver => "manifest::duplicate-environment-resolver",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManifestLint {
    UnusedProgram,
    UnusedSlot {
        name: String,
    },
    UnusedProvide {
        name: String,
    },
    DuplicateEnvironmentResolver {
        environment: String,
        resolver: String,
    },
}

impl ManifestLint {
    pub fn code(&self) -> LintCode {
        match self {
            ManifestLint::UnusedProgram => LintCode::UnusedProgram,
            ManifestLint::UnusedSlot { .. } => LintCode::UnusedSlot,
            ManifestLint::UnusedProvide { .. } => LintCode::UnusedProvide,
            ManifestLint::DuplicateEnvironmentResolver { .. } => {
                LintCode::DuplicateEnvironmentResolver
            }
        }
    }
}

impl fmt::Display for ManifestLint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestLint::UnusedProgram => {
                write!(f, "program is never referenced by bindings or exports")
            }
            ManifestLint::UnusedSlot { name } => {
                write!(f, "slot `{name}` is never bound")
            }
            ManifestLint::UnusedProvide { name } => {
                write!(f, "provide `{name}` is never used or exported")
            }
            ManifestLint::DuplicateEnvironmentResolver {
                environment,
                resolver,
            } => {
                write!(
                    f,
                    "environment `{environment}` declares resolver `{resolver}` more than once"
                )
            }
        }
    }
}

fn add_program_slot_uses<'a>(
    manifest: &'a Manifest,
    used_slots: &mut BTreeSet<&'a SlotName>,
    value: &'a InterpolatedString,
) {
    for part in &value.parts {
        let InterpolatedPart::Interpolation { source, query } = part else {
            continue;
        };
        if *source != InterpolationSource::Slots {
            continue;
        }
        let slot_name = query
            .split_once('.')
            .map_or(query.as_str(), |(first, _)| first);
        if slot_name.is_empty() {
            continue;
        }
        if let Some((slot_key, _)) = manifest.slots().get_key_value(slot_name) {
            used_slots.insert(slot_key);
        }
    }
}

pub fn lint_manifest(manifest: &Manifest) -> Vec<ManifestLint> {
    let mut lints = Vec::new();

    let mut bound_slots = BTreeSet::new();
    let mut bound_provides = BTreeSet::new();
    for (target, binding) in manifest.bindings() {
        if let BindingTarget::SelfSlot(slot_name) = target {
            bound_slots.insert(slot_name);
        }
        if let BindingSource::SelfProvide(provide_name) = &binding.from {
            bound_provides.insert(provide_name);
        }
    }

    let mut program_used_slots = BTreeSet::new();
    if let Some(program) = manifest.program() {
        for arg in &program.args.0 {
            add_program_slot_uses(manifest, &mut program_used_slots, arg);
        }
        for value in program.env.values() {
            add_program_slot_uses(manifest, &mut program_used_slots, value);
        }
    }

    let mut exported_provides = BTreeSet::new();
    for target in manifest.exports().values() {
        if let ExportTarget::SelfProvide(provide_name) = target {
            exported_provides.insert(provide_name);
        }
    }

    if manifest.program().is_some()
        && bound_slots.is_empty()
        && bound_provides.is_empty()
        && exported_provides.is_empty()
    {
        lints.push(ManifestLint::UnusedProgram);
    }

    for slot_name in manifest.slots().keys() {
        if !bound_slots.contains(slot_name) && !program_used_slots.contains(slot_name) {
            lints.push(ManifestLint::UnusedSlot {
                name: slot_name.to_string(),
            });
        }
    }

    for provide_name in manifest.provides().keys() {
        if !bound_provides.contains(provide_name) && !exported_provides.contains(provide_name) {
            lints.push(ManifestLint::UnusedProvide {
                name: provide_name.to_string(),
            });
        }
    }

    for (env_name, env) in manifest.environments() {
        let mut seen = BTreeSet::new();
        for resolver in &env.resolvers {
            if !seen.insert(resolver.as_str()) {
                lints.push(ManifestLint::DuplicateEnvironmentResolver {
                    environment: env_name.clone(),
                    resolver: resolver.clone(),
                });
            }
        }
    }

    lints
}
