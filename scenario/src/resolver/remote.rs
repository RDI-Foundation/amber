use std::{fmt, future::Future, pin::Pin, sync::Arc};

use url::Url;

use super::{Error, Resolution};

pub trait Backend: Send + Sync {
    fn resolve_url<'a>(
        &'a self,
        url: &'a Url,
    ) -> Pin<Box<dyn Future<Output = Result<Resolution, Error>> + Send + 'a>>;
}

#[derive(Clone)]
pub struct RemoteResolver {
    schemes: Arc<[Arc<str>]>,
    backend: Arc<dyn Backend>,
}

impl fmt::Debug for RemoteResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteResolver")
            .field("schemes", &self.schemes)
            .finish_non_exhaustive()
    }
}

impl RemoteResolver {
    pub fn new<I, S>(schemes: I, backend: Arc<dyn Backend>) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<Arc<str>>,
    {
        let schemes: Vec<Arc<str>> = schemes.into_iter().map(Into::into).collect();
        Self {
            schemes: schemes.into(),
            backend,
        }
    }

    pub fn schemes(&self) -> &[Arc<str>] {
        &self.schemes
    }

    pub fn resolve_url<'a>(
        &'a self,
        url: &'a Url,
    ) -> Pin<Box<dyn Future<Output = Result<Resolution, Error>> + Send + 'a>> {
        self.backend.resolve_url(url)
    }
}

/// Dispatches resolution to custom resolvers based on the URL scheme.
#[derive(Clone, Debug, Default)]
pub(super) struct RemoteDispatch {
    resolvers: Vec<RemoteResolver>,
}

impl RemoteDispatch {
    /// Find a resolver that supports the given scheme.
    pub(super) fn get(&self, scheme: &str) -> Option<RemoteResolver> {
        // Search backwards so that resolvers added "deeper" in the
        // component tree shadow those added at the root.
        self.resolvers
            .iter()
            .rev()
            .find(|resolver| resolver.schemes().iter().any(|s| &**s == scheme))
            .cloned()
    }

    /// Return a new dispatch instance including the provided resolver.
    pub(super) fn with_remote(&self, resolver: RemoteResolver) -> Self {
        let mut resolvers = self.resolvers.clone();
        resolvers.push(resolver);
        Self { resolvers }
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::Pin, sync::Arc};

    use url::Url;

    use super::{Backend, Error, RemoteDispatch, RemoteResolver, Resolution};

    struct NoopBackend;

    impl Backend for NoopBackend {
        fn resolve_url<'a>(
            &'a self,
            _url: &'a Url,
        ) -> Pin<Box<dyn Future<Output = Result<Resolution, Error>> + Send + 'a>> {
            Box::pin(std::future::ready(Err(Error::UnsupportedScheme {
                scheme: "unused".into(),
            })))
        }
    }

    fn resolver_for(schemes: &[&str]) -> RemoteResolver {
        RemoteResolver::new(schemes.iter().copied(), Arc::new(NoopBackend))
    }

    #[test]
    fn shadowing_prefers_latest_resolver() {
        let root = resolver_for(&["shadow"]);
        let child = resolver_for(&["shadow", "child"]);
        let dispatch = RemoteDispatch::default()
            .with_remote(root)
            .with_remote(child);

        let resolver = dispatch.get("shadow").expect("shadow resolver");
        assert!(resolver.schemes().iter().any(|s| s.as_ref() == "shadow"));
        assert!(resolver.schemes().iter().any(|s| s.as_ref() == "child"));
        assert_eq!(resolver.schemes().len(), 2);
    }

    #[test]
    fn with_remote_inherits_existing_resolvers() {
        let base = RemoteDispatch::default().with_remote(resolver_for(&["base"]));
        let child = base.with_remote(resolver_for(&["child"]));

        let base_resolver = child.get("base").expect("base resolver");
        assert!(base_resolver.schemes().iter().any(|s| s.as_ref() == "base"));

        let child_resolver = child.get("child").expect("child resolver");
        assert!(
            child_resolver
                .schemes()
                .iter()
                .any(|s| s.as_ref() == "child")
        );

        assert!(base.get("child").is_none());
    }
}
