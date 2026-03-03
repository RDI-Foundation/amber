use std::collections::HashSet;

use semver::Version;

pub fn parse_manifest_version(version: &str) -> Result<Version, String> {
    let raw = version.trim();
    if raw.is_empty() {
        return Err("version is empty".to_string());
    }
    let stripped = raw
        .strip_prefix('v')
        .ok_or_else(|| "version must start with 'v'".to_string())?;
    let parsed = Version::parse(stripped).map_err(|err| err.to_string())?;
    if !parsed.build.is_empty() {
        return Err("version must not include build metadata (+...)".to_string());
    }
    Ok(parsed)
}

pub fn runtime_tag(version: &Version) -> String {
    if version.pre.is_empty() {
        if version.major == 0 {
            format!("v0.{}", version.minor)
        } else {
            format!("v{}", version.major)
        }
    } else {
        let channel = prerelease_channel(version);
        if version.major == 0 {
            format!("v0.{}-{channel}", version.minor)
        } else {
            format!("v{}-{channel}", version.major)
        }
    }
}

#[allow(dead_code)]
pub fn floating_tags(version: &Version) -> Vec<String> {
    let mut tags = if version.pre.is_empty() {
        vec![
            format!("v{}.{}", version.major, version.minor),
            runtime_tag(version),
        ]
    } else {
        let prerelease = version.pre.to_string();
        if version.major == 0 {
            vec![
                format!("v0.{}-{prerelease}", version.minor),
                runtime_tag(version),
            ]
        } else {
            vec![
                format!("v{}.{}-{prerelease}", version.major, version.minor),
                format!("v{}-{prerelease}", version.major),
                runtime_tag(version),
            ]
        }
    };

    let mut deduped = Vec::new();
    let mut seen = HashSet::new();
    for tag in tags.drain(..) {
        if seen.insert(tag.clone()) {
            deduped.push(tag);
        }
    }
    deduped
}

fn prerelease_channel(version: &Version) -> &str {
    version
        .pre
        .as_str()
        .split('.')
        .next()
        .expect("prerelease should always have at least one segment")
}

#[cfg(test)]
mod tests {
    use super::{floating_tags, parse_manifest_version, runtime_tag};

    #[test]
    fn stable_major_one_tags() {
        let version = parse_manifest_version("v1.2.3").expect("valid stable version");
        assert_eq!(runtime_tag(&version), "v1");
        assert_eq!(floating_tags(&version), vec!["v1.2", "v1"]);
    }

    #[test]
    fn prerelease_major_one_tags() {
        let version = parse_manifest_version("v1.2.3-alpha.1").expect("valid prerelease version");
        assert_eq!(runtime_tag(&version), "v1-alpha");
        assert_eq!(
            floating_tags(&version),
            vec!["v1.2-alpha.1", "v1-alpha.1", "v1-alpha"]
        );
    }

    #[test]
    fn stable_major_zero_tags() {
        let version = parse_manifest_version("v0.2.3").expect("valid stable version");
        assert_eq!(runtime_tag(&version), "v0.2");
        assert_eq!(floating_tags(&version), vec!["v0.2"]);
    }

    #[test]
    fn prerelease_major_zero_tags() {
        let version = parse_manifest_version("v0.2.3-alpha.1").expect("valid prerelease version");
        assert_eq!(runtime_tag(&version), "v0.2-alpha");
        assert_eq!(floating_tags(&version), vec!["v0.2-alpha.1", "v0.2-alpha"]);
    }

    #[test]
    fn rejects_build_metadata() {
        let err = parse_manifest_version("v1.2.3+build.4")
            .expect_err("build metadata should be rejected");
        assert_eq!(err, "version must not include build metadata (+...)");
    }
}
