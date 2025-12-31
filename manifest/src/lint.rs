#![allow(unused_assignments)]

use std::{collections::BTreeSet, sync::Arc};

use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::{
    BindingSource, BindingTarget, ExportTarget, InterpolatedString, Manifest, ManifestSpans,
    SlotName,
};

#[allow(unused_assignments)]
#[derive(Clone, Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum ManifestLint {
    #[error("program is never referenced by bindings or exports (in component {component})")]
    #[diagnostic(
        code(manifest::unused_program),
        severity(Warning),
        help("Remove the `program` block if it is not needed, or ensure it is bound.")
    )]
    UnusedProgram {
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("unused `program`")]
        span: SourceSpan,
    },

    #[error("slot `{name}` is never bound (in component {component})")]
    #[diagnostic(
        code(manifest::unused_slot),
        severity(Warning),
        help("Remove the slot `{name}` if it is not needed, or bind it to a provider.")
    )]
    UnusedSlot {
        name: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("unused slot `{name}`")]
        span: SourceSpan,
    },

    #[error("provide `{name}` is never used or exported (in component {component})")]
    #[diagnostic(
        code(manifest::unused_provide),
        severity(Warning),
        help("Remove the provide `{name}` if it is not needed, or export/bind it.")
    )]
    UnusedProvide {
        name: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("unused provide `{name}`")]
        span: SourceSpan,
    },

    #[error(
        "environment `{environment}` declares resolver `{resolver}` more than once (in component \
         {component})"
    )]
    #[diagnostic(
        code(manifest::duplicate_environment_resolver),
        severity(Warning),
        help("Remove duplicate resolver entries.")
    )]
    DuplicateEnvironmentResolver {
        environment: String,
        resolver: String,
        component: String,
        #[source_code]
        src: NamedSource<Arc<str>>,
        #[label("duplicate resolver `{resolver}`")]
        span: SourceSpan,
    },
}

fn add_program_slot_uses<'a>(
    manifest: &'a Manifest,
    used_slots: &mut BTreeSet<&'a SlotName>,
    value: &'a InterpolatedString,
) -> bool {
    let used_all = value.visit_slot_uses(|slot_name| {
        if let Some((slot_key, _)) = manifest.slots().get_key_value(slot_name) {
            used_slots.insert(slot_key);
        }
    });
    if used_all {
        used_slots.extend(manifest.slots().keys());
    }
    used_all
}

pub fn lint_manifest(
    manifest: &Manifest,
    component: &str,
    src: NamedSource<Arc<str>>,
    spans: &ManifestSpans,
) -> Vec<ManifestLint> {
    let mut lints = Vec::new();
    let component = component.to_string();

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
        let mut used_all = false;
        for arg in &program.args.0 {
            used_all = add_program_slot_uses(manifest, &mut program_used_slots, arg);
            if used_all {
                break;
            }
        }
        if !used_all {
            for value in program.env.values() {
                used_all = add_program_slot_uses(manifest, &mut program_used_slots, value);
                if used_all {
                    break;
                }
            }
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
        let span = spans
            .program
            .as_ref()
            .map(|p| p.whole)
            .unwrap_or((0usize, 0usize).into());
        lints.push(ManifestLint::UnusedProgram {
            component: component.clone(),
            src: src.clone(),
            span,
        });
    }

    for slot_name in manifest.slots().keys() {
        if !bound_slots.contains(slot_name) && !program_used_slots.contains(slot_name) {
            let span = spans
                .slots
                .get(slot_name.as_str())
                .map(|s| s.name)
                .unwrap_or((0usize, 0usize).into());
            lints.push(ManifestLint::UnusedSlot {
                name: slot_name.to_string(),
                component: component.clone(),
                src: src.clone(),
                span,
            });
        }
    }

    for provide_name in manifest.provides().keys() {
        if !bound_provides.contains(provide_name) && !exported_provides.contains(provide_name) {
            let span = spans
                .provides
                .get(provide_name.as_str())
                .map(|p| p.capability.name)
                .unwrap_or((0usize, 0usize).into());
            lints.push(ManifestLint::UnusedProvide {
                name: provide_name.to_string(),
                component: component.clone(),
                src: src.clone(),
                span,
            });
        }
    }

    for (env_name, env) in manifest.environments() {
        let mut seen = BTreeSet::new();
        for (idx, resolver) in env.resolvers.iter().enumerate() {
            if !seen.insert(resolver.as_str()) {
                let span = spans
                    .environments
                    .get(env_name.as_str())
                    .and_then(|e| e.resolvers.get(idx).map(|(_, s)| *s))
                    .unwrap_or((0usize, 0usize).into());
                lints.push(ManifestLint::DuplicateEnvironmentResolver {
                    environment: env_name.clone(),
                    resolver: resolver.clone(),
                    component: component.clone(),
                    src: src.clone(),
                    span,
                });
            }
        }
    }

    lints
}
