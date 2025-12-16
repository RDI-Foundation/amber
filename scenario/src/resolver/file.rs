use std::io;

use url::Url;

use super::{Error, Resolution};
use crate::cache::Cacheability;

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
        let manifest = tokio::fs::read_to_string(path).await?.parse()?;
        Ok(Resolution {
            url: url.clone(),
            manifest,
            cacheability: Cacheability::ByDigestOnly,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicUsize, Ordering},
    };

    use url::Url;

    use crate::{manifest::Manifest, resolver::Resolver};

    static FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_tmp_dir() -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp");
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(contents: &str) -> Self {
            let id = FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path =
                test_tmp_dir().join(format!("file-resolver-{}-{id}.json5", std::process::id()));
            fs::write(&path, contents).unwrap();
            Self { path }
        }

        fn url(&self) -> Url {
            Url::from_file_path(&self.path).unwrap()
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    #[tokio::test]
    async fn reads_manifest() {
        let contents = r#"{ manifest_version: "1.0.0" }"#;
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
        let contents = r#"{ manifest_version: "1.0.0" }"#;
        let file = TempFile::new(contents);
        let url = file.url();

        let resolver = Resolver::new();
        let manifest: Manifest = contents.parse().unwrap();
        crate::resolver::tests::assert_digest_mismatch_errors(&resolver, &url, &manifest).await;
    }
}
