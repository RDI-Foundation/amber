use amber_manifest::ExportName;
use amber_scenario::{Moniker, Scenario};

use crate::Provenance;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayPlan {
    pub scenario: Scenario,
    pub provenance: Provenance,
    pub scopes: Vec<OverlayScopePlan>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayScopePlan {
    pub root_moniker: Moniker,
    pub overlays: Vec<OverlayExport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OverlayExport {
    pub export: ExportName,
    pub display_name: String,
}
