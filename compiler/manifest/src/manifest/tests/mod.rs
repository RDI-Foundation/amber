use super::*;
use crate::{CapabilityKind, NetworkProtocol};

mod basics;
mod bindings;
mod child_templates;
mod components;
mod exports;
mod mounts;

fn parse_raw(input: &str) -> RawManifest {
    amber_json5::parse(input).unwrap()
}

fn find_binding<'a>(manifest: &'a Manifest, target: &BindingTarget) -> &'a Binding {
    manifest
        .bindings()
        .iter()
        .find(|binding| &binding.target == target)
        .map(|binding| &binding.binding)
        .expect("binding")
}
