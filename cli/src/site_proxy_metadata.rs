use std::path::Path;

use amber_compiler::{
    mesh::{PROXY_METADATA_FILENAME, PROXY_METADATA_VERSION, ProxyMetadata},
    reporter::docker_compose::COMPOSE_FILENAME,
    run_plan::RunSitePlan,
};
use amber_proxy::{parse_compose_proxy_metadata, parse_proxy_metadata_json};
use miette::Result;

pub(crate) fn load_site_proxy_metadata(site_plan: &RunSitePlan) -> Result<ProxyMetadata> {
    let (source_name, metadata) =
        if let Some(raw) = site_plan.artifact_files.get(PROXY_METADATA_FILENAME) {
            (
                PROXY_METADATA_FILENAME,
                parse_proxy_metadata_json(raw, Path::new(PROXY_METADATA_FILENAME))?,
            )
        } else if let Some(raw) = site_plan.artifact_files.get(COMPOSE_FILENAME) {
            (
                COMPOSE_FILENAME,
                parse_compose_proxy_metadata(raw, Path::new(COMPOSE_FILENAME))?,
            )
        } else {
            return Err(miette::miette!(
                "site is missing {} or {}",
                PROXY_METADATA_FILENAME,
                COMPOSE_FILENAME
            ));
        };

    if metadata.version != PROXY_METADATA_VERSION {
        return Err(miette::miette!(
            "proxy metadata version {} in {} is not supported",
            metadata.version,
            source_name
        ));
    }

    Ok(metadata)
}
