use amber_manifest::ExportName;
use amber_scenario::{Moniker, Scenario};
use serde_json::Value;

use crate::Provenance;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Governance {
    pub scenario: Scenario,
    pub provenance: Provenance,
    pub scopes: Vec<GovernedScope>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernedScope {
    pub root_moniker: Moniker,
    pub policies: Vec<GovernedPolicy>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernedPolicy {
    pub export: ExportName,
    pub args: Option<Value>,
}
