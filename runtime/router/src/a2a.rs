use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
};

use aho_corasick::{AhoCorasick, Input, MatchKind};
use amber_mesh::{HttpRoutePlugin, InboundRoute, InboundTarget, MeshProtocol, OutboundRoute};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::Method;
use serde_json::{Value, value::RawValue};
use url::Url;

use super::{BodyMode, HttpExchangePlugin, RewriteContext, RewriteFlow, StreamBodyRewriter};

const WELL_KNOWN_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
const ABSTRACT_ROUTE_SCHEME: &str = "amber";
const ABSTRACT_ROUTE_HOST: &str = "route";
const LOOPBACK_URL_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "[::1]"];

pub(super) fn is_agent_card_path(path: &str) -> bool {
    path == WELL_KNOWN_AGENT_CARD_PATH
}

pub(super) fn is_json_content_type(content_type: Option<&str>) -> bool {
    let Some(content_type) = content_type else {
        return false;
    };
    let media_type = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

#[derive(Clone, Debug)]
pub(super) struct UrlRewriteTable {
    #[cfg(test)]
    route_by_loopback_port: HashMap<u16, String>,
    #[cfg(test)]
    route_by_host_port: HashMap<(String, u16), String>,
    #[cfg(test)]
    local_target_by_route: HashMap<String, LocalRouteTarget>,
    upcast_plan: Option<Arc<StreamRewritePlan>>,
    downcast_plan: Option<Arc<StreamRewritePlan>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalRouteTarget {
    host: String,
    port: u16,
}

#[derive(Clone, Debug)]
struct StreamRewritePlan {
    matcher: Arc<AhoCorasick>,
    replacements: Arc<[Vec<u8>]>,
    patterns: Arc<[Vec<u8>]>,
    max_pattern_len: usize,
}

impl UrlRewriteTable {
    pub(super) fn from_routes(inbound: &[InboundRoute], outbound: &[OutboundRoute]) -> Self {
        let mut route_by_loopback_port_raw: HashMap<u16, Option<String>> = HashMap::new();
        let mut route_by_host_port_raw: HashMap<(String, u16), Option<String>> = HashMap::new();
        let mut local_target_by_route: HashMap<String, LocalRouteTarget> = HashMap::new();

        for route in outbound {
            if !a2a_http_route(route.protocol, &route.http_plugins) {
                continue;
            }
            let Some(host) = normalize_host(route.listen_addr.as_deref().unwrap_or("127.0.0.1"))
            else {
                continue;
            };
            register_route_mapping(
                route.route_id.as_str(),
                host.clone(),
                route.listen_port,
                &mut route_by_loopback_port_raw,
                &mut route_by_host_port_raw,
            );
            insert_route_target_if_absent(
                &mut local_target_by_route,
                route.route_id.as_str(),
                LocalRouteTarget {
                    host,
                    port: route.listen_port,
                },
            );
        }

        for route in inbound {
            if !a2a_http_route(route.protocol, &route.http_plugins) {
                continue;
            }
            let InboundTarget::Local { port } = route.target else {
                continue;
            };
            register_route_mapping(
                route.route_id.as_str(),
                "127.0.0.1".to_string(),
                port,
                &mut route_by_loopback_port_raw,
                &mut route_by_host_port_raw,
            );
            insert_route_target_if_absent(
                &mut local_target_by_route,
                route.route_id.as_str(),
                LocalRouteTarget {
                    host: "127.0.0.1".to_string(),
                    port,
                },
            );
        }

        let route_by_loopback_port = retain_unique_mappings(route_by_loopback_port_raw);
        let route_by_host_port = retain_unique_mappings(route_by_host_port_raw);
        let upcast_plan = build_upcast_plan(&route_by_host_port, &route_by_loopback_port);
        let downcast_plan = build_downcast_plan(&local_target_by_route);

        Self {
            #[cfg(test)]
            route_by_loopback_port,
            #[cfg(test)]
            route_by_host_port,
            #[cfg(test)]
            local_target_by_route,
            upcast_plan,
            downcast_plan,
        }
    }

    #[cfg(test)]
    fn from_outbound_routes(routes: &[OutboundRoute]) -> Self {
        Self::from_routes(&[], routes)
    }

    #[cfg(test)]
    fn upcast(&self, original: &Url) -> Option<Url> {
        if !matches!(original.scheme(), "http" | "https") {
            return None;
        }
        let host = normalize_host(original.host_str()?)?;
        let port = original.port_or_known_default()?;
        let route_id = self
            .route_by_host_port
            .get(&(host.clone(), port))
            .or_else(|| {
                is_loopback_host(host.as_str())
                    .then(|| self.route_by_loopback_port.get(&port))
                    .flatten()
            })?;

        let token = URL_SAFE_NO_PAD.encode(route_id.as_bytes());
        let mut rewritten =
            Url::parse(&format!("{ABSTRACT_ROUTE_SCHEME}://{ABSTRACT_ROUTE_HOST}/")).ok()?;
        rewritten.set_path(&format!("/{token}{}", original.path()));
        rewritten.set_query(original.query());
        rewritten.set_fragment(original.fragment());
        Some(rewritten)
    }

    #[cfg(test)]
    fn downcast(&self, original: &Url) -> Option<Url> {
        let (route_id, path) = parse_abstract_route(original)?;
        let target = self.local_target_by_route.get(route_id.as_str())?;
        let host = format_url_host(target.host.as_str());
        let mut rewritten = Url::parse(&format!("http://{host}:{}/", target.port)).ok()?;
        rewritten.set_path(path.as_str());
        rewritten.set_query(original.query());
        rewritten.set_fragment(original.fragment());
        Some(rewritten)
    }

    fn stream_rewriter(&self, mode: UrlRewriteMode) -> Option<UrlStreamRewriter> {
        let plan = match mode {
            UrlRewriteMode::Upcast => self.upcast_plan.clone(),
            UrlRewriteMode::Downcast => self.downcast_plan.clone(),
        }?;
        Some(UrlStreamRewriter::new(plan))
    }

    fn rewrite_bytes(&self, raw: &mut Vec<u8>, mode: UrlRewriteMode) -> bool {
        let Some(mut rewriter) = self.stream_rewriter(mode) else {
            return false;
        };
        let rewritten = rewriter.rewrite_chunk(raw.as_slice(), true);
        if rewritten == *raw {
            return false;
        }
        *raw = rewritten;
        true
    }
}

fn a2a_http_route(protocol: MeshProtocol, plugins: &[HttpRoutePlugin]) -> bool {
    protocol == MeshProtocol::Http && plugins.contains(&HttpRoutePlugin::A2a)
}

fn register_route_mapping(
    route_id: &str,
    host: String,
    port: u16,
    route_by_loopback_port_raw: &mut HashMap<u16, Option<String>>,
    route_by_host_port_raw: &mut HashMap<(String, u16), Option<String>>,
) {
    insert_unique_or_invalidate(
        route_by_host_port_raw,
        (host.clone(), port),
        route_id.to_string(),
    );
    if is_loopback_host(host.as_str()) {
        insert_unique_or_invalidate(route_by_loopback_port_raw, port, route_id.to_string());
    }
}

fn insert_route_target_if_absent(
    map: &mut HashMap<String, LocalRouteTarget>,
    route_id: &str,
    target: LocalRouteTarget,
) {
    map.entry(route_id.to_string()).or_insert(target);
}

fn insert_unique_or_invalidate<K, V>(map: &mut HashMap<K, Option<V>>, key: K, value: V)
where
    K: std::cmp::Eq + std::hash::Hash,
    V: PartialEq,
{
    match map.entry(key) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(Some(value));
        }
        std::collections::hash_map::Entry::Occupied(mut entry) => match entry.get() {
            Some(existing) if existing == &value => {}
            _ => {
                entry.insert(None);
            }
        },
    }
}

fn retain_unique_mappings<K, V>(raw: HashMap<K, Option<V>>) -> HashMap<K, V>
where
    K: std::cmp::Eq + std::hash::Hash,
{
    raw.into_iter()
        .filter_map(|(key, value)| value.map(|resolved| (key, resolved)))
        .collect()
}

fn build_upcast_plan(
    route_by_host_port: &HashMap<(String, u16), String>,
    route_by_loopback_port: &HashMap<u16, String>,
) -> Option<Arc<StreamRewritePlan>> {
    let mut map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

    for ((host, port), route_id) in route_by_host_port {
        let token = URL_SAFE_NO_PAD.encode(route_id.as_bytes());
        let abstract_base = format!("{ABSTRACT_ROUTE_SCHEME}://{ABSTRACT_ROUTE_HOST}/{token}");
        for scheme in ["http", "https"] {
            map.insert(
                format!("{scheme}://{}:{port}", format_url_host(host)).into_bytes(),
                abstract_base.as_bytes().to_vec(),
            );
        }
    }

    for (port, route_id) in route_by_loopback_port {
        let token = URL_SAFE_NO_PAD.encode(route_id.as_bytes());
        let abstract_base = format!("{ABSTRACT_ROUTE_SCHEME}://{ABSTRACT_ROUTE_HOST}/{token}");
        for host in LOOPBACK_URL_HOSTS {
            for scheme in ["http", "https"] {
                map.insert(
                    format!("{scheme}://{host}:{port}").into_bytes(),
                    abstract_base.as_bytes().to_vec(),
                );
            }
        }
    }

    build_stream_rewrite_plan(map)
}

fn build_downcast_plan(
    local_target_by_route: &HashMap<String, LocalRouteTarget>,
) -> Option<Arc<StreamRewritePlan>> {
    let mut map: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

    for (route_id, target) in local_target_by_route {
        let token = URL_SAFE_NO_PAD.encode(route_id.as_bytes());
        map.insert(
            format!("{ABSTRACT_ROUTE_SCHEME}://{ABSTRACT_ROUTE_HOST}/{token}").into_bytes(),
            format!(
                "http://{}:{}",
                format_url_host(target.host.as_str()),
                target.port
            )
            .into_bytes(),
        );
    }

    build_stream_rewrite_plan(map)
}

fn build_stream_rewrite_plan(map: HashMap<Vec<u8>, Vec<u8>>) -> Option<Arc<StreamRewritePlan>> {
    if map.is_empty() {
        return None;
    }

    let mut entries = map.into_iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        right
            .0
            .len()
            .cmp(&left.0.len())
            .then_with(|| left.0.cmp(&right.0))
    });
    let patterns = entries
        .iter()
        .map(|(pattern, _)| pattern.clone())
        .collect::<Vec<_>>();
    let max_pattern_len = patterns.iter().map(Vec::len).max().unwrap_or(0);
    let matcher = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostLongest)
        .build(patterns.iter().map(|pattern| pattern.as_slice()))
        .ok()?;
    let replacements = entries
        .into_iter()
        .map(|(_, replacement)| replacement)
        .collect::<Vec<_>>();

    Some(Arc::new(StreamRewritePlan {
        matcher: Arc::new(matcher),
        replacements: replacements.into(),
        patterns: patterns.into(),
        max_pattern_len,
    }))
}

pub(super) struct A2aUrlRewritePlugin {
    table: Arc<UrlRewriteTable>,
}

impl A2aUrlRewritePlugin {
    pub(super) fn new(table: Arc<UrlRewriteTable>) -> Self {
        Self { table }
    }
}

impl HttpExchangePlugin for A2aUrlRewritePlugin {
    fn matches(&self, _req: &http::request::Parts) -> bool {
        true
    }

    fn request_body_mode(&self, _req: &http::request::Parts) -> BodyMode {
        BodyMode::Stream
    }

    fn response_body_mode(&self, req: &http::request::Parts) -> BodyMode {
        if is_agent_card_path(req.uri.path()) {
            return BodyMode::Collect;
        }
        BodyMode::Stream
    }

    fn request_stream_rewriter(
        &self,
        ctx: &RewriteContext,
        parts: &http::request::Parts,
    ) -> Option<Box<dyn StreamBodyRewriter>> {
        if matches!(parts.method, Method::GET | Method::HEAD) {
            return None;
        }
        let mode = match ctx.flow {
            RewriteFlow::Inbound => UrlRewriteMode::Downcast,
            RewriteFlow::Outbound => UrlRewriteMode::Upcast,
        };
        self.table
            .stream_rewriter(mode)
            .map(|rewriter| Box::new(rewriter) as Box<dyn StreamBodyRewriter>)
    }

    fn response_stream_rewriter(
        &self,
        ctx: &RewriteContext,
        _parts: &http::response::Parts,
    ) -> Option<Box<dyn StreamBodyRewriter>> {
        if ctx.request_is_agent_card {
            return None;
        }
        let mode = match ctx.flow {
            RewriteFlow::Inbound => UrlRewriteMode::Upcast,
            RewriteFlow::Outbound => UrlRewriteMode::Downcast,
        };
        self.table
            .stream_rewriter(mode)
            .map(|rewriter| Box::new(rewriter) as Box<dyn StreamBodyRewriter>)
    }

    fn rewrite_request(
        &self,
        ctx: &RewriteContext,
        _parts: &mut http::request::Parts,
        body: &mut Vec<u8>,
    ) -> bool {
        let mode = match ctx.flow {
            RewriteFlow::Inbound => UrlRewriteMode::Downcast,
            RewriteFlow::Outbound => UrlRewriteMode::Upcast,
        };
        self.table.rewrite_bytes(body, mode)
    }

    fn rewrite_response(
        &self,
        ctx: &RewriteContext,
        _parts: &mut http::response::Parts,
        body: &mut Vec<u8>,
    ) -> bool {
        if ctx.flow == RewriteFlow::Inbound && ctx.request_is_agent_card {
            return rewrite_inbound_agent_card(body, ctx.route_id.as_ref());
        }
        let mode = match ctx.flow {
            RewriteFlow::Inbound => UrlRewriteMode::Upcast,
            RewriteFlow::Outbound => UrlRewriteMode::Downcast,
        };
        let mut rewritten = self.table.rewrite_bytes(body, mode);
        if ctx.request_is_agent_card && rewritten {
            rewritten |= strip_signatures(body);
        }
        rewritten
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UrlRewriteMode {
    Upcast,
    Downcast,
}

#[derive(Clone)]
struct UrlStreamRewriter {
    plan: Arc<StreamRewritePlan>,
    pending: Vec<u8>,
    previous_input_byte: Option<u8>,
}

impl UrlStreamRewriter {
    fn new(plan: Arc<StreamRewritePlan>) -> Self {
        Self {
            plan,
            pending: Vec::new(),
            previous_input_byte: None,
        }
    }

    fn rewrite_window(&self, source: &[u8], emit_len: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(emit_len);
        let mut cursor = 0usize;

        while cursor < emit_len {
            let Some(matched) = self
                .plan
                .matcher
                .find(Input::new(source).span(cursor..emit_len))
            else {
                break;
            };
            let start = matched.start();
            if start >= emit_len {
                break;
            }
            let end = matched.end();
            if end > emit_len {
                break;
            }

            let previous = if start == 0 {
                self.previous_input_byte
            } else {
                source.get(start.saturating_sub(1)).copied()
            };
            let next = source.get(end).copied();

            if !is_url_prefix_boundary(previous) || !is_url_suffix_boundary(next) {
                let advance = start.saturating_add(1);
                output.extend_from_slice(&source[cursor..advance]);
                cursor = advance;
                continue;
            }

            output.extend_from_slice(&source[cursor..start]);
            output.extend_from_slice(&self.plan.replacements[matched.pattern().as_usize()]);
            cursor = end;
        }

        output.extend_from_slice(&source[cursor..emit_len]);
        output
    }

    fn suffix_prefix_keep_len(&self) -> usize {
        let max_keep = self.plan.max_pattern_len.min(self.pending.len());
        for keep_len in (1..=max_keep).rev() {
            let suffix = &self.pending[self.pending.len() - keep_len..];
            if self
                .plan
                .patterns
                .iter()
                .any(|pattern| pattern.len() >= keep_len && pattern[..keep_len] == *suffix)
            {
                return keep_len;
            }
        }
        0
    }
}

impl StreamBodyRewriter for UrlStreamRewriter {
    fn rewrite_chunk(&mut self, chunk: &[u8], is_final: bool) -> Vec<u8> {
        self.pending.extend_from_slice(chunk);

        let keep_len = if is_final {
            0
        } else {
            self.suffix_prefix_keep_len()
        };
        let emit_len = self.pending.len().saturating_sub(keep_len);
        if emit_len == 0 && !is_final {
            return Vec::new();
        }

        let rewritten = self.rewrite_window(self.pending.as_slice(), emit_len);
        self.previous_input_byte = emit_len
            .checked_sub(1)
            .and_then(|index| self.pending.get(index).copied());

        if is_final {
            self.pending.clear();
        } else {
            self.pending.drain(..emit_len);
        }

        rewritten
    }
}

type BorrowedRawJsonObject<'a> = BTreeMap<String, &'a RawValue>;
type OwnedRawJsonObject = BTreeMap<String, Box<RawValue>>;

fn parse_raw_json_object(raw: &[u8]) -> Option<BorrowedRawJsonObject<'_>> {
    serde_json::from_slice::<BorrowedRawJsonObject<'_>>(raw).ok()
}

fn encode_raw_json_object(fields: OwnedRawJsonObject) -> Option<Vec<u8>> {
    serde_json::to_vec(&fields).ok()
}

fn parse_json_string(raw: &RawValue) -> Option<String> {
    serde_json::from_str::<String>(raw.get()).ok()
}

fn encode_json_string(value: &str) -> Option<Box<RawValue>> {
    let json = serde_json::to_string(value).ok()?;
    RawValue::from_string(json).ok()
}

pub(super) fn collect_dynamic_capability_refs(raw: &[u8]) -> BTreeSet<String> {
    let Ok(value) = serde_json::from_slice::<Value>(raw) else {
        return BTreeSet::new();
    };
    let mut refs = BTreeSet::new();
    collect_dynamic_capability_refs_from_value(&value, &mut refs);
    refs
}

fn collect_dynamic_capability_refs_from_value(value: &Value, refs: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            for (key, field_value) in fields {
                if key == "ref"
                    && let Value::String(raw_ref) = field_value
                    && raw_ref.starts_with("amber://ref/")
                {
                    refs.insert(raw_ref.clone());
                    continue;
                }
                collect_dynamic_capability_refs_from_value(field_value, refs);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_dynamic_capability_refs_from_value(item, refs);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

pub(super) fn rewrite_dynamic_capability_ref_fields(
    raw: &mut Vec<u8>,
    replacements: &BTreeMap<String, String>,
) -> bool {
    if replacements.is_empty() {
        return false;
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(raw) else {
        return false;
    };
    if !rewrite_dynamic_capability_refs_in_value(&mut value, replacements) {
        return false;
    }
    let Ok(encoded) = serde_json::to_vec(&value) else {
        return false;
    };
    *raw = encoded;
    true
}

fn rewrite_dynamic_capability_refs_in_value(
    value: &mut Value,
    replacements: &BTreeMap<String, String>,
) -> bool {
    match value {
        Value::Object(fields) => {
            let mut rewritten = false;
            for (key, field_value) in fields {
                if key == "ref"
                    && let Value::String(raw_ref) = field_value
                    && let Some(replacement) = replacements.get(raw_ref)
                {
                    *raw_ref = replacement.clone();
                    rewritten = true;
                    continue;
                }
                rewritten |= rewrite_dynamic_capability_refs_in_value(field_value, replacements);
            }
            rewritten
        }
        Value::Array(items) => {
            let mut rewritten = false;
            for item in items {
                rewritten |= rewrite_dynamic_capability_refs_in_value(item, replacements);
            }
            rewritten
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn rewrite_supported_interface_urls(
    raw_interfaces: &RawValue,
    abstract_base: &str,
) -> Option<Box<RawValue>> {
    let Ok(mut interfaces) = serde_json::from_str::<Vec<Box<RawValue>>>(raw_interfaces.get())
    else {
        return None;
    };

    let mut rewritten = false;
    for interface in &mut interfaces {
        let Ok(mut fields) = serde_json::from_str::<OwnedRawJsonObject>(interface.get()) else {
            continue;
        };
        let Some(raw_url) = fields.get_mut("url") else {
            continue;
        };
        let Some(url_raw) = parse_json_string(raw_url.as_ref()) else {
            continue;
        };
        let Some(updated) = rewrite_loopback_url(url_raw.as_str(), abstract_base) else {
            continue;
        };
        if updated != url_raw {
            *raw_url = encode_json_string(updated.as_str())?;
            let json = serde_json::to_string(&fields).ok()?;
            *interface = RawValue::from_string(json).ok()?;
            rewritten = true;
        }
    }

    if !rewritten {
        return None;
    }

    let json = serde_json::to_string(&interfaces).ok()?;
    RawValue::from_string(json).ok()
}

fn rewrite_legacy_top_level_url(raw_url: &RawValue, abstract_base: &str) -> Option<Box<RawValue>> {
    let url_raw = parse_json_string(raw_url)?;
    let updated = rewrite_loopback_url(url_raw.as_str(), abstract_base)?;
    if updated == url_raw {
        return None;
    }
    encode_json_string(updated.as_str())
}

fn strip_signatures(raw: &mut Vec<u8>) -> bool {
    let Some(object) = parse_raw_json_object(raw.as_slice()) else {
        return false;
    };
    if !object.contains_key("signatures") {
        return false;
    }

    let mut fields = BTreeMap::new();
    for (key, value) in object {
        if key == "signatures" {
            continue;
        }
        fields.insert(key, value.to_owned());
    }

    let Some(encoded) = encode_raw_json_object(fields) else {
        return false;
    };
    *raw = encoded;
    true
}

fn rewrite_inbound_agent_card(raw: &mut Vec<u8>, route_id: &str) -> bool {
    let Some(object) = parse_raw_json_object(raw.as_slice()) else {
        return false;
    };

    let token = URL_SAFE_NO_PAD.encode(route_id.as_bytes());
    let abstract_base = format!("{ABSTRACT_ROUTE_SCHEME}://{ABSTRACT_ROUTE_HOST}/{token}");

    let mut rewritten_interfaces = object
        .get("supportedInterfaces")
        .and_then(|raw_interfaces| {
            rewrite_supported_interface_urls(raw_interfaces, abstract_base.as_str())
        });

    // Legacy top-level "url" (removed in newer spec versions but seen in the wild).
    let mut rewritten_url = object
        .get("url")
        .and_then(|raw_url| rewrite_legacy_top_level_url(raw_url, abstract_base.as_str()));

    if rewritten_interfaces.is_none() && rewritten_url.is_none() {
        return false;
    }

    let mut fields = BTreeMap::new();
    for (key, value) in object {
        if key == "signatures" {
            continue;
        }
        if key == "supportedInterfaces"
            && let Some(updated) = rewritten_interfaces.take()
        {
            fields.insert(key, updated);
            continue;
        }
        if key == "url"
            && let Some(updated) = rewritten_url.take()
        {
            fields.insert(key, updated);
            continue;
        }
        fields.insert(key, value.to_owned());
    }

    let Some(encoded) = encode_raw_json_object(fields) else {
        return false;
    };
    *raw = encoded;
    true
}

fn rewrite_loopback_url(original: &str, abstract_base: &str) -> Option<String> {
    let parsed = Url::parse(original).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }

    let host = normalize_host(parsed.host_str()?)?;
    if !is_loopback_host(host.as_str()) {
        return None;
    }

    let mut rewritten = format!("{abstract_base}{}", parsed.path());
    if let Some(query) = parsed.query() {
        rewritten.push('?');
        rewritten.push_str(query);
    }
    if let Some(fragment) = parsed.fragment() {
        rewritten.push('#');
        rewritten.push_str(fragment);
    }
    Some(rewritten)
}

#[cfg(test)]
fn parse_abstract_route(url: &Url) -> Option<(String, String)> {
    if url.scheme() != ABSTRACT_ROUTE_SCHEME || url.host_str() != Some(ABSTRACT_ROUTE_HOST) {
        return None;
    }
    let raw_path = url.path().strip_prefix('/')?;
    if raw_path.is_empty() {
        return None;
    }
    let (token, tail) = raw_path.split_once('/').unwrap_or((raw_path, ""));
    if token.is_empty() {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(token.as_bytes()).ok()?;
    let route_id = String::from_utf8(decoded).ok()?;
    let path = if tail.is_empty() {
        "/".to_string()
    } else {
        format!("/{tail}")
    };
    Some((route_id, path))
}

fn normalize_host(host: &str) -> Option<String> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    Some(normalized)
}

fn is_loopback_host(host: &str) -> bool {
    host == "127.0.0.1" || host == "localhost" || host == "::1"
}

fn format_url_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn is_url_prefix_boundary(byte: Option<u8>) -> bool {
    byte.is_none_or(|value| {
        !matches!(
            value,
            b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'+'
                | b'-'
                | b'.'
                | b'_'
                | b'/'
                | b':'
                | b'%'
        )
    })
}

fn is_url_suffix_boundary(byte: Option<u8>) -> bool {
    byte.is_none_or(|value| {
        matches!(
            value,
            b'/' | b'?'
                | b'#'
                | b'"'
                | b'\''
                | b'<'
                | b'>'
                | b')'
                | b']'
                | b'}'
                | b','
                | b';'
                | b':'
                | b' '
                | b'\t'
                | b'\r'
                | b'\n'
        )
    })
}

#[cfg(test)]
mod tests {
    use amber_mesh::{InboundRoute, InboundTarget, OutboundRoute};

    use super::*;

    fn a2a_outbound_route(
        route_id: &str,
        listen_port: u16,
        listen_addr: Option<&str>,
    ) -> OutboundRoute {
        OutboundRoute {
            route_id: route_id.to_string(),
            slot: "slot".to_string(),
            capability_kind: Some("a2a".to_string()),
            capability_profile: None,
            listen_port,
            listen_addr: listen_addr.map(ToString::to_string),
            protocol: MeshProtocol::Http,
            http_plugins: vec![HttpRoutePlugin::A2a],
            peer_addr: "127.0.0.1:31000".to_string(),
            peer_id: "peer".to_string(),
            capability: "agent".to_string(),
        }
    }

    fn a2a_inbound_route(route_id: &str, port: u16) -> InboundRoute {
        InboundRoute {
            route_id: route_id.to_string(),
            capability: "agent".to_string(),
            capability_kind: Some("a2a".to_string()),
            capability_profile: None,
            protocol: MeshProtocol::Http,
            http_plugins: vec![HttpRoutePlugin::A2a],
            target: InboundTarget::Local { port },
            allowed_issuers: vec!["peer".to_string()],
        }
    }

    #[test]
    fn url_rewrite_table_round_trips_route_url() {
        let table = UrlRewriteTable::from_outbound_routes(&[a2a_outbound_route(
            "component:a:agent:http",
            20000,
            None,
        )]);
        let source =
            Url::parse("http://127.0.0.1:20000/cgi-bin/a2a?x=1#frag").expect("source url parse");
        let abstracted = table.upcast(&source).expect("upcast local slot url");
        assert_eq!(abstracted.scheme(), ABSTRACT_ROUTE_SCHEME);
        assert_eq!(abstracted.host_str(), Some(ABSTRACT_ROUTE_HOST));

        let restored = table
            .downcast(&abstracted)
            .expect("downcast abstract route url");
        assert_eq!(restored.as_str(), source.as_str());
    }

    #[test]
    fn from_routes_supports_inbound_agent_card_upcast() {
        let table =
            UrlRewriteTable::from_routes(&[a2a_inbound_route("component:a:agent:http", 8080)], &[]);
        let source = Url::parse("http://127.0.0.1:8080/.well-known/agent-card.json")
            .expect("source url parse");
        let abstracted = table.upcast(&source).expect("upcast local provide url");
        assert!(abstracted.as_str().starts_with("amber://route/"));
    }

    #[test]
    fn collect_dynamic_capability_refs_only_sees_ref_fields() {
        let raw = br#"{
            "ref": "amber://ref/root",
            "note": "amber://ref/ignored",
            "nested": {
                "ref": "amber://ref/nested"
            }
        }"#;

        let refs = collect_dynamic_capability_refs(raw);
        assert_eq!(
            refs.into_iter().collect::<Vec<_>>(),
            vec![
                "amber://ref/nested".to_string(),
                "amber://ref/root".to_string(),
            ]
        );
    }

    #[test]
    fn rewrite_dynamic_capability_ref_fields_preserves_non_ref_strings() {
        let mut raw = br#"{
            "ref": "amber://ref/root",
            "note": "amber://ref/ignored",
            "nested": {
                "ref": "amber://ref/nested"
            }
        }"#
        .to_vec();
        let replacements = BTreeMap::from([
            (
                "amber://ref/root".to_string(),
                "http://127.0.0.1:23100/root".to_string(),
            ),
            (
                "amber://ref/nested".to_string(),
                "http://127.0.0.1:23100/nested".to_string(),
            ),
        ]);

        assert!(rewrite_dynamic_capability_ref_fields(
            &mut raw,
            &replacements,
        ));
        let value: Value = serde_json::from_slice(&raw).expect("rewritten json should parse");
        assert_eq!(value["ref"], "http://127.0.0.1:23100/root");
        assert_eq!(value["nested"]["ref"], "http://127.0.0.1:23100/nested");
        assert_eq!(value["note"], "amber://ref/ignored");
    }

    #[test]
    fn upcast_rejects_ambiguous_host_port_mapping() {
        let table = UrlRewriteTable::from_outbound_routes(&[
            a2a_outbound_route("component:a:agent:http", 20000, Some("127.0.0.1")),
            a2a_outbound_route("component:b:agent:http", 20000, Some("127.0.0.1")),
        ]);
        let source = Url::parse("http://127.0.0.1:20000/a2a").expect("source url parse");
        assert!(table.upcast(&source).is_none());
    }

    #[test]
    fn downcast_uses_first_outbound_target_for_duplicate_route_id() {
        let table = UrlRewriteTable::from_outbound_routes(&[
            a2a_outbound_route("component:a:agent:http", 20000, None),
            a2a_outbound_route("component:a:agent:http", 20001, None),
        ]);
        let token = URL_SAFE_NO_PAD.encode("component:a:agent:http".as_bytes());
        let abstracted = Url::parse(format!("amber://route/{token}/a2a").as_str())
            .expect("abstracted url parse");
        let rewritten = table.downcast(&abstracted).expect("downcast route url");
        assert_eq!(rewritten.as_str(), "http://127.0.0.1:20000/a2a");
    }

    #[test]
    fn downcast_falls_back_to_inbound_route_when_outbound_missing() {
        let table =
            UrlRewriteTable::from_routes(&[a2a_inbound_route("component:a:agent:http", 8080)], &[]);
        let token = URL_SAFE_NO_PAD.encode("component:a:agent:http".as_bytes());
        let abstracted = Url::parse(format!("amber://route/{token}/a2a").as_str())
            .expect("abstracted url parse");
        let rewritten = table.downcast(&abstracted).expect("downcast route url");
        assert_eq!(rewritten.as_str(), "http://127.0.0.1:8080/a2a");
    }

    #[test]
    fn rewrite_bytes_rewrites_url_instances() {
        let table = UrlRewriteTable::from_outbound_routes(&[a2a_outbound_route(
            "component:a:agent:http",
            20000,
            None,
        )]);
        let mut raw = br#"{"parts":[{"url":"http://127.0.0.1:20000/a2a"}]}"#.to_vec();
        assert!(table.rewrite_bytes(&mut raw, UrlRewriteMode::Upcast));
        let rewritten = String::from_utf8(raw).expect("utf8");
        assert!(rewritten.contains("amber://route/"));
        assert!(rewritten.contains("/a2a"));
    }

    #[test]
    fn stream_rewriter_handles_pattern_split_across_chunks() {
        let table = UrlRewriteTable::from_outbound_routes(&[a2a_outbound_route(
            "component:a:agent:http",
            20000,
            None,
        )]);
        let mut rewriter = table
            .stream_rewriter(UrlRewriteMode::Upcast)
            .expect("stream rewriter");
        let chunk_a = br#"{"url":"http://127.0.0.1:"#;
        let chunk_b = br#"20000/a2a"}"#;
        let mut out = rewriter.rewrite_chunk(chunk_a, false);
        out.extend_from_slice(rewriter.rewrite_chunk(chunk_b, true).as_slice());
        let rewritten = String::from_utf8(out).expect("utf8");
        assert!(rewritten.contains("amber://route/"));
        assert!(rewritten.contains("/a2a"));
    }

    #[test]
    fn stream_rewriter_keeps_partial_match_prefix_until_complete() {
        let table = UrlRewriteTable::from_outbound_routes(&[a2a_outbound_route(
            "component:a:agent:http",
            20001,
            None,
        )]);
        let mut rewriter = table
            .stream_rewriter(UrlRewriteMode::Upcast)
            .expect("stream rewriter");
        let chunk_a = br#"{"url":"http://127.0.0.1:2000"#;
        let chunk_b = br#"1/cgi-bin/a2a"}"#;
        let mut out = rewriter.rewrite_chunk(chunk_a, false);
        out.extend_from_slice(rewriter.rewrite_chunk(chunk_b, true).as_slice());
        let rewritten = String::from_utf8(out).expect("utf8");
        assert!(rewritten.contains("amber://route/"));
        assert!(rewritten.contains("/cgi-bin/a2a"));
        assert!(!rewritten.contains("http://127.0.0.1:20001"));
    }

    #[test]
    fn strip_signatures_removes_only_when_present() {
        let mut raw = br#"{"url":"http://127.0.0.1:20000","signatures":[{"sig":"abc"}]}"#.to_vec();
        assert!(strip_signatures(&mut raw));
        let value: Value = serde_json::from_slice(raw.as_slice()).expect("value");
        assert!(value.get("signatures").is_none());
    }

    #[test]
    fn rewrite_inbound_agent_card_rewrites_urls_and_strips_signatures() {
        let route_id = "component:a:agent:http";
        let token = URL_SAFE_NO_PAD.encode(route_id.as_bytes());
        let mut raw = br#"{"supportedInterfaces":[{"url":"http://127.0.0.1:8080/a2a?x=1#frag"}],"signatures":[{"sig":"abc"}]}"#.to_vec();

        assert!(rewrite_inbound_agent_card(&mut raw, route_id));

        let value: Value = serde_json::from_slice(raw.as_slice()).expect("value");
        assert!(value.get("signatures").is_none());
        let url = value
            .get("supportedInterfaces")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(Value::as_object)
            .and_then(|entry| entry.get("url"))
            .and_then(Value::as_str)
            .expect("supportedInterfaces[0].url");
        assert_eq!(url, format!("amber://route/{token}/a2a?x=1#frag").as_str());
    }

    #[test]
    fn rewrite_inbound_agent_card_rewrites_legacy_top_level_url_and_strips_signatures() {
        let route_id = "component:a:agent:http";
        let token = URL_SAFE_NO_PAD.encode(route_id.as_bytes());
        let mut raw =
            br#"{"name":"agent","url":"http://localhost:8080/a2a","signatures":[{"sig":"abc"}]}"#
                .to_vec();

        assert!(rewrite_inbound_agent_card(&mut raw, route_id));

        let value: Value = serde_json::from_slice(raw.as_slice()).expect("value");
        assert!(value.get("signatures").is_none());
        let expected_url = format!("amber://route/{token}/a2a");
        assert_eq!(
            value.get("url").and_then(Value::as_str),
            Some(expected_url.as_str())
        );
    }

    #[test]
    fn rewrite_inbound_agent_card_keeps_non_object_interface_entries() {
        let route_id = "component:a:agent:http";
        let token = URL_SAFE_NO_PAD.encode(route_id.as_bytes());
        let mut raw =
            br#"{"supportedInterfaces":[42,{"url":"http://127.0.0.1:8080/a2a"}],"signatures":[{"sig":"abc"}]}"#
                .to_vec();

        assert!(rewrite_inbound_agent_card(&mut raw, route_id));

        let value: Value = serde_json::from_slice(raw.as_slice()).expect("value");
        let interfaces = value
            .get("supportedInterfaces")
            .and_then(Value::as_array)
            .expect("supportedInterfaces");
        assert_eq!(interfaces.first(), Some(&serde_json::json!(42)));
        let expected_url = format!("amber://route/{token}/a2a");
        assert_eq!(
            interfaces
                .get(1)
                .and_then(Value::as_object)
                .and_then(|entry| entry.get("url"))
                .and_then(Value::as_str),
            Some(expected_url.as_str())
        );
    }

    #[test]
    fn rewrite_inbound_agent_card_noop_preserves_bytes() {
        let route_id = "component:a:agent:http";
        let original =
            br#"{"supportedInterfaces":[{"url":"https://api.example.com/a2a"}],"signatures":[{"sig":"abc"}]}"#
                .to_vec();
        let mut raw = original.clone();

        assert!(!rewrite_inbound_agent_card(&mut raw, route_id));
        assert_eq!(raw, original);
    }
}
