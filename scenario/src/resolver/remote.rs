use std::{collections::HashMap, fmt, future::Future, pin::Pin, sync::Arc};

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

#[derive(Clone, Debug, Default)]
pub(super) struct RemoteDispatch {
    head: Option<Arc<RemoteDispatchNode>>,
}

#[derive(Debug)]
struct RemoteDispatchNode {
    parent: Option<Arc<RemoteDispatchNode>>,
    by_scheme: HashMap<Arc<str>, RemoteResolver>,
}

impl RemoteDispatch {
    pub(super) fn get(&self, scheme: &str) -> Option<RemoteResolver> {
        let mut current = self.head.as_deref();
        while let Some(node) = current {
            if let Some(resolver) = node.by_scheme.get(scheme) {
                return Some(resolver.clone());
            }
            current = node.parent.as_deref();
        }
        None
    }

    pub(super) fn with_remote(&self, resolver: RemoteResolver) -> Self {
        let mut by_scheme = HashMap::with_capacity(resolver.schemes().len());
        for scheme in resolver.schemes() {
            by_scheme.insert(scheme.clone(), resolver.clone());
        }

        Self {
            head: Some(Arc::new(RemoteDispatchNode {
                parent: self.head.clone(),
                by_scheme,
            })),
        }
    }
}
