use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use amber_manifest::{Manifest, ManifestDigest, ProgramEntrypoint};
use amber_scenario::{
    Component, ComponentId, Moniker, Program, ProgramCommon, ProgramImage, ProgramMount,
};

use super::collect_program_slot_uses;
use crate::linker::program_lowering::lower_program;

#[test]
fn collect_program_slot_uses_includes_slot_conditions() {
    let manifest: Manifest = r#"
            {
              manifest_version: "0.2.0",
              program: {
                image: "app",
                entrypoint: [
                  "app",
                  { when: "slots.api", argv: ["--serve"] },
                ],
              },
              slots: {
                api: { kind: "http" },
              },
            }
        "#
    .parse()
    .expect("manifest");
    let component = Component {
        id: ComponentId(0),
        parent: None,
        moniker: Moniker::from(Arc::<str>::from("/")),
        digest: ManifestDigest::new([0; 32]),
        config: None,
        config_schema: None,
        program: Some(
            lower_program(ComponentId(0), manifest.program().expect("program"), None)
                .expect("program should lower"),
        ),
        slots: manifest
            .slots()
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    assert_eq!(
        collect_program_slot_uses(&component),
        HashSet::from(["api".to_string()])
    );
}

#[test]
fn collect_program_slot_uses_includes_lowered_mount_slots() {
    let manifest: Manifest = r#"
            {
              manifest_version: "0.2.0",
              slots: {
                state: { kind: "storage" },
              },
            }
        "#
    .parse()
    .expect("manifest");
    let component = Component {
        id: ComponentId(0),
        parent: None,
        moniker: Moniker::from(Arc::<str>::from("/")),
        digest: ManifestDigest::new([0; 32]),
        config: None,
        config_schema: None,
        program: Some(Program::Image(ProgramImage {
            image: "app".to_string(),
            entrypoint: ProgramEntrypoint::default(),
            common: ProgramCommon {
                env: BTreeMap::new(),
                network: None,
                mounts: vec![ProgramMount::Slot {
                    path: "/var/lib/app".to_string(),
                    slot: "state".to_string(),
                }],
            },
        })),
        slots: manifest
            .slots()
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    assert_eq!(
        collect_program_slot_uses(&component),
        HashSet::from(["state".to_string()])
    );
}
