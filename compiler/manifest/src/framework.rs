use std::sync::OnceLock;

use crate::{CapabilityDecl, CapabilityKind, ExperimentalFeature, FrameworkCapabilityName};

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
    pub required_experimental_feature: Option<ExperimentalFeature>,
    pub description: &'static str,
}

pub fn framework_capabilities() -> &'static [FrameworkCapabilitySpec] {
    static CAPS: OnceLock<Vec<FrameworkCapabilitySpec>> = OnceLock::new();
    CAPS.get_or_init(|| {
        vec![
            FrameworkCapabilitySpec {
                name: FrameworkCapabilityName::try_from("docker")
                    .expect("framework capability names are static and valid"),
                decl: CapabilityDecl {
                    kind: CapabilityKind::Docker,
                    profile: None,
                },
                binding_shape: FrameworkBindingShape::Url,
                required_experimental_feature: Some(ExperimentalFeature::Docker),
                description: "Docker Engine API access via the Amber framework gateway",
            },
            FrameworkCapabilitySpec {
                name: FrameworkCapabilityName::try_from("kvm")
                    .expect("framework capability names are static and valid"),
                decl: CapabilityDecl {
                    kind: CapabilityKind::Kvm,
                    profile: None,
                },
                binding_shape: FrameworkBindingShape::Opaque,
                required_experimental_feature: Some(ExperimentalFeature::Kvm),
                description: "KVM device access for hardware-accelerated virtualization",
            },
        ]
    })
    .as_slice()
}

pub fn framework_capability(name: &str) -> Option<&'static FrameworkCapabilitySpec> {
    framework_capabilities()
        .iter()
        .find(|cap| cap.name.as_str() == name)
}
