use amber_manifest::ExportName;
use amber_scenario::{Moniker, Scenario};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Governance {
    pub scenario: Scenario,
    pub scopes: Vec<GovernedScope>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernedScope {
    pub root_moniker: Moniker,
    pub policies: Vec<ExportName>,
}
