use http::Method;
use serde_json::Value;
use url::Url;

use super::{BodyMode, HttpExchangePlugin, RewriteContext};

const WELL_KNOWN_AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";

pub(super) struct AgentCardUrlRewritePlugin;

impl AgentCardUrlRewritePlugin {
    pub(super) fn new() -> Self {
        Self
    }
}

impl HttpExchangePlugin for AgentCardUrlRewritePlugin {
    fn matches(&self, req: &http::request::Parts) -> bool {
        req.method == Method::GET && req.uri.path() == WELL_KNOWN_AGENT_CARD_PATH
    }

    fn response_body_mode(&self, _req: &http::request::Parts) -> BodyMode {
        BodyMode::Collect
    }

    fn rewrite_response(
        &self,
        ctx: &RewriteContext<'_>,
        _parts: &mut http::response::Parts,
        body: &mut Vec<u8>,
    ) -> bool {
        let Some(requester_base) = ctx.requester_base else {
            return false;
        };
        rewrite_agent_card_urls(body, requester_base)
    }
}

fn rewrite_agent_card_urls(raw: &mut Vec<u8>, requester_base: &Url) -> bool {
    let Ok(mut value) = serde_json::from_slice::<Value>(raw) else {
        return false;
    };

    let mut rewritten = false;

    if let Some(card_url) = value.get_mut("url") {
        rewritten |= rewrite_agent_card_url(card_url, requester_base);
    }

    rewritten |=
        rewrite_supported_interface_urls(value.get_mut("supportedInterfaces"), requester_base);
    rewritten |=
        rewrite_supported_interface_urls(value.get_mut("supported_interfaces"), requester_base);

    if let Some(object) = value.as_object_mut() {
        rewritten |= object.remove("signatures").is_some();
    }

    if !rewritten {
        return false;
    }

    let Ok(encoded) = serde_json::to_vec(&value) else {
        return false;
    };
    *raw = encoded;
    true
}

fn rewrite_supported_interface_urls(value: Option<&mut Value>, requester_base: &Url) -> bool {
    let Some(interfaces) = value else {
        return false;
    };
    let Some(interfaces) = interfaces.as_array_mut() else {
        return false;
    };

    let mut rewritten = false;
    for entry in interfaces {
        let Some(entry) = entry.as_object_mut() else {
            continue;
        };
        let Some(url) = entry.get_mut("url") else {
            continue;
        };
        rewritten |= rewrite_agent_card_url(url, requester_base);
    }
    rewritten
}

fn rewrite_agent_card_url(value: &mut Value, requester_base: &Url) -> bool {
    let Some(original) = value.as_str() else {
        return false;
    };
    let Ok(mut rewritten) = Url::parse(original) else {
        return false;
    };
    if rewritten.set_scheme(requester_base.scheme()).is_err() {
        return false;
    }
    if rewritten.set_host(requester_base.host_str()).is_err() {
        return false;
    }
    if rewritten.set_port(requester_base.port()).is_err() {
        return false;
    }
    if rewritten.as_str() == original {
        return false;
    }
    *value = Value::String(rewritten.into());
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_agent_card_urls_rewrites_supported_interface_url() {
        let requester_base = Url::parse("http://127.0.0.1:20000").expect("requester base");
        let mut raw = serde_json::to_vec(&serde_json::json!({
            "name": "agent",
            "provider": { "url": "https://provider.example.com" },
            "supportedInterfaces": [
                {
                    "url": "http://127.0.0.1:8080/a2a",
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": "1.0"
                }
            ]
        }))
        .expect("serialize card");
        assert!(rewrite_agent_card_urls(&mut raw, &requester_base));
        let rewritten: serde_json::Value = serde_json::from_slice(raw.as_slice()).expect("parse");

        assert_eq!(
            rewritten["supportedInterfaces"][0]["url"].as_str(),
            Some("http://127.0.0.1:20000/a2a")
        );
        assert_eq!(
            rewritten["provider"]["url"].as_str(),
            Some("https://provider.example.com")
        );
    }

    #[test]
    fn rewrite_agent_card_urls_rewrites_legacy_top_level_url() {
        let requester_base = Url::parse("http://127.0.0.1:20000").expect("requester base");
        let mut raw = serde_json::to_vec(&serde_json::json!({
            "name": "agent",
            "url": "http://127.0.0.1:8080/"
        }))
        .expect("serialize card");
        assert!(rewrite_agent_card_urls(&mut raw, &requester_base));
        let rewritten: serde_json::Value = serde_json::from_slice(raw.as_slice()).expect("parse");

        assert_eq!(rewritten["url"].as_str(), Some("http://127.0.0.1:20000/"));
    }

    #[test]
    fn rewrite_agent_card_urls_strips_signatures() {
        let requester_base = Url::parse("http://127.0.0.1:20000").expect("requester base");
        let mut raw = serde_json::to_vec(&serde_json::json!({
            "name": "agent",
            "supportedInterfaces": [
                {
                    "url": "http://127.0.0.1:8080/a2a",
                    "protocolBinding": "JSONRPC",
                    "protocolVersion": "1.0"
                }
            ],
            "signatures": [
                {
                    "protected": "a",
                    "signature": "b"
                }
            ]
        }))
        .expect("serialize card");
        assert!(rewrite_agent_card_urls(&mut raw, &requester_base));
        let rewritten: serde_json::Value = serde_json::from_slice(raw.as_slice()).expect("parse");

        assert!(rewritten.get("signatures").is_none());
    }
}
