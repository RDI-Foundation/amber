use std::collections::HashSet;

use semver::Version;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestVersionSpec {
    Concrete(Version),
    Wildcard(WildcardVersionSpec),
}

impl ManifestVersionSpec {
    pub fn seed_version(&self) -> &Version {
        match self {
            Self::Concrete(version) => version,
            Self::Wildcard(spec) => spec.seed_version(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WildcardVersionSpec {
    seed: Version,
}

impl WildcardVersionSpec {
    pub fn seed_version(&self) -> &Version {
        &self.seed
    }
}

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

pub fn parse_manifest_version_spec(version: &str) -> Result<ManifestVersionSpec, String> {
    let raw = version.trim();
    if !raw.ends_with(".x") {
        return parse_manifest_version(raw).map(ManifestVersionSpec::Concrete);
    }

    let prefix = raw
        .strip_suffix('x')
        .expect("wildcard versions should always end with x");
    let seed_version = format!("{prefix}0");
    let parsed = parse_manifest_version(&seed_version)
        .map_err(|err| format!("invalid wildcard version {raw}: {err}"))?;

    Ok(ManifestVersionSpec::Wildcard(WildcardVersionSpec {
        seed: parsed,
    }))
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
    use super::{
        ManifestVersionSpec, floating_tags, parse_manifest_version, parse_manifest_version_spec,
        runtime_tag,
    };

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

    #[test]
    fn parses_concrete_manifest_version_spec() {
        let parsed =
            parse_manifest_version_spec("v1.2.3").expect("concrete version spec should parse");
        match parsed {
            ManifestVersionSpec::Concrete(version) => {
                assert_eq!(version.to_string(), "1.2.3");
            }
            ManifestVersionSpec::Wildcard(_) => panic!("expected concrete version"),
        }
    }

    #[test]
    fn parses_stable_wildcard_manifest_version_spec() {
        let parsed = parse_manifest_version_spec("v1.2.x")
            .expect("stable wildcard version spec should parse");
        match parsed {
            ManifestVersionSpec::Wildcard(spec) => {
                assert_eq!(spec.seed_version().to_string(), "1.2.0");
            }
            ManifestVersionSpec::Concrete(_) => panic!("expected wildcard version"),
        }
    }

    #[test]
    fn parses_prerelease_wildcard_manifest_version_spec() {
        let parsed = parse_manifest_version_spec("v1.2.3-alpha.x")
            .expect("prerelease wildcard version spec should parse");
        match parsed {
            ManifestVersionSpec::Wildcard(spec) => {
                assert_eq!(spec.seed_version().to_string(), "1.2.3-alpha.0");
            }
            ManifestVersionSpec::Concrete(_) => panic!("expected wildcard version"),
        }
    }

    #[test]
    fn rejects_invalid_wildcard_version_spec() {
        let err = parse_manifest_version_spec("v1.x")
            .expect_err("invalid wildcard version spec should fail");
        assert_eq!(
            err,
            "invalid wildcard version v1.x: unexpected end of input while parsing minor version \
             number"
        );
    }
}
