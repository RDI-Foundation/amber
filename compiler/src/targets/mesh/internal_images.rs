use std::{collections::HashSet, env};

use amber_images::{AMBER_HELPER, AMBER_ROUTER, AMBER_SIDECAR, ImageRef};

const DEV_IMAGE_TAGS_ENV: &str = "AMBER_DEV_IMAGE_TAGS";

#[derive(Clone, Debug)]
pub(crate) struct InternalImages {
    pub(crate) sidecar: String,
    pub(crate) helper: String,
    pub(crate) router: String,
}

pub(crate) fn resolve_internal_images() -> Result<InternalImages, String> {
    let mut images = InternalImages {
        sidecar: default_reference(&AMBER_SIDECAR),
        helper: default_reference(&AMBER_HELPER),
        router: default_reference(&AMBER_ROUTER),
    };

    let raw = match env::var(DEV_IMAGE_TAGS_ENV) {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return Ok(images),
        Err(err) => {
            return Err(format!("failed to read {DEV_IMAGE_TAGS_ENV}: {err}"));
        }
    };

    let raw = raw.trim();
    if raw.is_empty() {
        return Err(format!(
            "{DEV_IMAGE_TAGS_ENV} is set but empty; expected format \
             \"router=<tag>,sidecar=<tag>,helper=<tag>\""
        ));
    }

    let mut seen = HashSet::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(format!(
                "{DEV_IMAGE_TAGS_ENV} contains an empty entry; expected format \
                 \"router=<tag>,sidecar=<tag>,helper=<tag>\""
            ));
        }

        let mut parts = entry.splitn(2, '=');
        let key = parts.next().unwrap().trim();
        let value = parts.next().ok_or_else(|| {
            format!("{DEV_IMAGE_TAGS_ENV} entry \"{entry}\" is missing '='; expected key=value")
        })?;
        let value = value.trim();

        if key.is_empty() {
            return Err(format!(
                "{DEV_IMAGE_TAGS_ENV} entry \"{entry}\" is missing a key; expected key=value"
            ));
        }
        if value.is_empty() {
            return Err(format!(
                "{DEV_IMAGE_TAGS_ENV} entry \"{entry}\" is missing a tag; expected key=tag"
            ));
        }
        if !seen.insert(key.to_string()) {
            return Err(format!(
                "{DEV_IMAGE_TAGS_ENV} contains duplicate key \"{key}\""
            ));
        }

        match key {
            "router" => images.router = override_reference(&AMBER_ROUTER, value),
            "sidecar" => images.sidecar = override_reference(&AMBER_SIDECAR, value),
            "helper" => images.helper = override_reference(&AMBER_HELPER, value),
            _ => {
                return Err(format!(
                    "{DEV_IMAGE_TAGS_ENV} contains unknown key \"{key}\"; expected router, \
                     sidecar, helper"
                ));
            }
        }
    }

    Ok(images)
}

fn default_reference(image: &ImageRef) -> String {
    image.reference.to_string()
}

fn override_reference(image: &ImageRef, tag: &str) -> String {
    format!("{}/{}:{}", image.registry, image.name, tag)
}
