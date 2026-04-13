use std::{
    collections::{BTreeMap, BTreeSet},
    env,
};

pub mod versioning;

pub const DEV_IMAGE_TAGS_ENV: &str = "AMBER_DEV_IMAGE_TAGS";
pub const INTERNAL_IMAGE_OVERRIDE_KEYS: &[&str] = &[
    "router",
    "helper",
    "provisioner",
    "docker_gateway",
    "site_controller",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ImageRef {
    pub name: &'static str,
    pub tag: &'static str,
    pub registry: &'static str,
    pub reference: &'static str,
}

pub fn override_reference(image: &ImageRef, tag: &str) -> String {
    format!("{}/{}:{}", image.registry, image.name, tag)
}

pub fn parse_dev_image_tag_overrides(
    allowed_keys: &[&str],
) -> Result<BTreeMap<String, String>, String> {
    match env::var(DEV_IMAGE_TAGS_ENV) {
        Ok(raw) => parse_dev_image_tag_overrides_from_raw(Some(raw.as_str()), allowed_keys),
        Err(env::VarError::NotPresent) => Ok(BTreeMap::new()),
        Err(err) => Err(format!("failed to read {DEV_IMAGE_TAGS_ENV}: {err}")),
    }
}

pub fn parse_dev_image_tag_overrides_from_raw(
    raw: Option<&str>,
    allowed_keys: &[&str],
) -> Result<BTreeMap<String, String>, String> {
    let Some(raw) = raw else {
        return Ok(BTreeMap::new());
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(format!(
            "{DEV_IMAGE_TAGS_ENV} is set but empty; expected format {}",
            expected_override_format(allowed_keys),
        ));
    }

    let allowed = allowed_keys
        .iter()
        .map(|key| (*key).to_string())
        .collect::<BTreeSet<_>>();
    let mut overrides = BTreeMap::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(format!(
                "{DEV_IMAGE_TAGS_ENV} contains an empty entry; expected format {}",
                expected_override_format(allowed_keys),
            ));
        }

        let mut parts = entry.splitn(2, '=');
        let key = parts.next().unwrap_or_default().trim();
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
        if !allowed.contains(key) {
            return Err(format!(
                "{DEV_IMAGE_TAGS_ENV} contains unknown key \"{key}\"; expected {}",
                allowed_keys.join(", "),
            ));
        }
        if overrides
            .insert(key.to_string(), value.to_string())
            .is_some()
        {
            return Err(format!(
                "{DEV_IMAGE_TAGS_ENV} contains duplicate key \"{key}\""
            ));
        }
    }
    Ok(overrides)
}

fn expected_override_format(allowed_keys: &[&str]) -> String {
    let entries = allowed_keys
        .iter()
        .map(|key| format!("{key}=<tag>"))
        .collect::<Vec<_>>()
        .join(",");
    format!("\"{entries}\"")
}

include!(concat!(env!("OUT_DIR"), "/images.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dev_image_tag_overrides_accepts_site_controller_key() {
        let overrides = parse_dev_image_tag_overrides_from_raw(
            Some("router=dev-router,site_controller=dev-controller"),
            INTERNAL_IMAGE_OVERRIDE_KEYS,
        )
        .expect("dev image tag overrides should parse");

        assert_eq!(
            overrides.get("router").map(String::as_str),
            Some("dev-router")
        );
        assert_eq!(
            overrides.get("site_controller").map(String::as_str),
            Some("dev-controller")
        );
    }

    #[test]
    fn parse_dev_image_tag_overrides_rejects_unknown_key() {
        let err = parse_dev_image_tag_overrides_from_raw(
            Some("router=dev-router,unknown=dev"),
            INTERNAL_IMAGE_OVERRIDE_KEYS,
        )
        .expect_err("unknown override keys should be rejected");

        assert!(err.contains("unknown key"));
        assert!(err.contains("site_controller"));
    }
}
