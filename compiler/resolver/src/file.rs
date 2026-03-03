use std::{io, sync::Arc};

use url::Url;

use super::{Error, Resolution};

#[derive(Clone, Copy, Debug, Default)]
pub struct FileResolver;

impl FileResolver {
    pub fn new() -> Self {
        Default::default()
    }

    pub(super) async fn resolve_url(&self, url: &Url) -> Result<Resolution, Error> {
        let path = url.to_file_path().map_err(|()| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid file URL: {url}"),
            )
        })?;
        let source: Arc<str> = tokio::fs::read_to_string(&path).await?.into();
        let parsed =
            amber_manifest::ParsedManifest::parse_named(path.display().to_string(), source)?;
        let manifest = parsed.manifest;
        let source = parsed.source;
        let spans = parsed.spans;
        Ok(Resolution {
            url: url.clone(),
            manifest,
            source,
            spans,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use amber_manifest::Manifest;
    use tempfile::NamedTempFile;
    use url::Url;

    use crate::Resolver;

    struct TempFile {
        file: NamedTempFile,
    }

    impl TempFile {
        fn new(contents: &str) -> Self {
            let mut file = tempfile::Builder::new()
                .prefix("file-resolver-")
                .suffix(".json5")
                .tempfile()
                .unwrap();
            file.write_all(contents.as_bytes()).unwrap();
            file.flush().unwrap();
            Self { file }
        }

        fn url(&self) -> Url {
            Url::from_file_path(self.file.path()).unwrap()
        }
    }

    #[tokio::test]
    async fn reads_manifest() {
        let contents = r#"{ manifest_version: "0.1.0" }"#;
        let file = TempFile::new(contents);
        let url = file.url();

        let resolver = Resolver::new();
        let res = resolver.resolve(&url, None).await.unwrap();

        let expected: Manifest = contents.parse().unwrap();
        assert_eq!(res.url, url);
        assert_eq!(res.manifest, expected);
    }

    #[tokio::test]
    async fn digest_mismatch_errors() {
        let contents = r#"{ manifest_version: "0.1.0" }"#;
        let file = TempFile::new(contents);
        let url = file.url();

        let resolver = Resolver::new();
        let manifest: Manifest = contents.parse().unwrap();
        crate::tests::assert_digest_mismatch_errors(&resolver, &url, &url, &manifest).await;
    }
}
