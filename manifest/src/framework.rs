use std::sync::OnceLock;

use crate::{CapabilityDecl, FrameworkCapabilityName};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameworkBindingShape {
    Url,
    Opaque,
}

#[derive(Clone, Debug)]
pub struct FrameworkCapabilitySpec {
    pub name: FrameworkCapabilityName,
    pub decl: CapabilityDecl,
    pub binding_shape: FrameworkBindingShape,
    pub description: &'static str,
}

pub fn framework_capabilities() -> &'static [FrameworkCapabilitySpec] {
    static CAPS: OnceLock<Vec<FrameworkCapabilitySpec>> = OnceLock::new();
    CAPS.get_or_init(Vec::new).as_slice()
}

pub fn framework_capability(name: &str) -> Option<&'static FrameworkCapabilitySpec> {
    framework_capabilities()
        .iter()
        .find(|cap| cap.name.as_str() == name)
}
