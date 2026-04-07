use std::collections::BTreeMap;

use amber_manifest::ManifestRef;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TemplateMode {
    Exact,
    Bounded,
    Open,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TemplateListResponse {
    pub templates: Vec<TemplateSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TemplateSummary {
    pub name: String,
    pub mode: TemplateMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub possible_backends: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TemplateDescribeResponse {
    pub name: String,
    pub manifest: TemplateManifestDescription,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, ConfigFieldDescription>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings: BTreeMap<String, BindingInputDescription>,
    #[serde(default, skip_serializing_if = "TemplateExportsDescription::is_empty")]
    pub exports: TemplateExportsDescription,
    #[serde(default, skip_serializing_if = "TemplateLimits::is_empty")]
    pub limits: TemplateLimits,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub possible_backends: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TemplateManifestDescription {
    pub mode: TemplateMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest: Option<ManifestRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub manifests: Vec<ManifestRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ConfigFieldDescription {
    pub state: InputState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BindingInputDescription {
    pub state: InputState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatible_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputState {
    Prefilled,
    Open,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TemplateExportsDescription {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visible: Vec<String>,
}

impl TemplateExportsDescription {
    fn is_empty(&self) -> bool {
        self.visible.is_empty()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TemplateLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_live_children: Option<u64>,
}

impl TemplateLimits {
    fn is_empty(&self) -> bool {
        self.max_live_children.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CreateChildRequest {
    pub template: String,
    pub name: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_manifest_request",
        deserialize_with = "deserialize_manifest_request"
    )]
    pub manifest: Option<ManifestRef>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub config: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub bindings: BTreeMap<String, BindingInput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TemplateResolveRequest {
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_manifest_request",
        deserialize_with = "deserialize_manifest_request"
    )]
    pub manifest: Option<ManifestRef>,
}

fn serialize_manifest_request<S>(
    manifest: &Option<ManifestRef>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match manifest {
        None => serializer.serialize_none(),
        Some(manifest) if manifest.digest.is_none() => {
            serializer.serialize_str(manifest.url.as_str())
        }
        Some(manifest) => manifest.serialize(serializer),
    }
}

fn deserialize_manifest_request<'de, D>(deserializer: D) -> Result<Option<ManifestRef>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<ManifestRef>::deserialize(deserializer)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BindingInput {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CreateChildResponse {
    pub child: ChildHandle,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub outputs: BTreeMap<String, OutputHandle>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChildHandle {
    pub name: String,
    pub selector: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OutputHandle {
    pub selector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChildListResponse {
    pub children: Vec<ChildSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChildSummary {
    pub name: String,
    pub state: ChildState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ChildDescribeResponse {
    pub name: String,
    pub state: ChildState,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub outputs: BTreeMap<String, OutputHandle>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChildState {
    CreateRequested,
    CreatePrepared,
    CreateCommittedHidden,
    Live,
    CreateAborted,
    DestroyRequested,
    DestroyRetracted,
    DestroyCommitted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SnapshotResponse {
    pub scenario: Value,
    pub placement: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProtocolErrorResponse {
    pub code: ProtocolErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolErrorCode {
    Unauthorized,
    UnknownTemplate,
    UnknownChild,
    NameConflict,
    ManifestRequired,
    ManifestNotAllowed,
    InvalidManifestRef,
    ManifestDigestMismatch,
    ManifestResolutionFailed,
    InvalidConfig,
    InvalidBinding,
    BindingSourceNotFound,
    BindingTypeMismatch,
    PlacementUnsatisfied,
    SiteNotActive,
    ScopeNotAllowed,
    ControlStateUnavailable,
    PrepareFailed,
    PublishFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_list_response_matches_design_fixture() {
        let response = TemplateListResponse {
            templates: vec![
                TemplateSummary {
                    name: "worker".to_string(),
                    mode: TemplateMode::Exact,
                    possible_backends: vec!["compose".to_string()],
                },
                TemplateSummary {
                    name: "arbitrary_job".to_string(),
                    mode: TemplateMode::Open,
                    possible_backends: vec!["direct".to_string(), "vm".to_string()],
                },
            ],
        };

        let json = serde_json::to_value(&response).expect("serialize template list");
        assert_eq!(
            json,
            serde_json::json!({
                "templates": [
                    {
                        "name": "worker",
                        "mode": "exact",
                        "possible_backends": ["compose"]
                    },
                    {
                        "name": "arbitrary_job",
                        "mode": "open",
                        "possible_backends": ["direct", "vm"]
                    }
                ]
            })
        );
    }

    #[test]
    fn template_describe_response_matches_design_fixture() {
        let response = TemplateDescribeResponse {
            name: "worker".to_string(),
            manifest: TemplateManifestDescription {
                mode: TemplateMode::Exact,
                manifest: Some(
                    "https://example.com/worker.json5"
                        .parse()
                        .expect("manifest ref"),
                ),
                manifests: Vec::new(),
            },
            config: BTreeMap::from([
                (
                    "mode".to_string(),
                    ConfigFieldDescription {
                        state: InputState::Prefilled,
                        value: Some(serde_json::json!("batch")),
                        required: None,
                    },
                ),
                (
                    "count".to_string(),
                    ConfigFieldDescription {
                        state: InputState::Open,
                        value: None,
                        required: Some(true),
                    },
                ),
            ]),
            bindings: BTreeMap::from([
                (
                    "db".to_string(),
                    BindingInputDescription {
                        state: InputState::Prefilled,
                        selector: Some("slots.db".to_string()),
                        optional: None,
                        compatible_kind: None,
                        candidates: Vec::new(),
                    },
                ),
                (
                    "seed".to_string(),
                    BindingInputDescription {
                        state: InputState::Open,
                        selector: None,
                        optional: Some(false),
                        compatible_kind: Some("url".to_string()),
                        candidates: vec![
                            "provides.api".to_string(),
                            "children.prev-job.exports.result".to_string(),
                        ],
                    },
                ),
            ]),
            exports: TemplateExportsDescription {
                visible: vec!["result".to_string()],
            },
            limits: TemplateLimits {
                max_live_children: Some(64),
            },
            possible_backends: vec!["compose".to_string()],
        };

        let json = serde_json::to_value(&response).expect("serialize template description");
        assert_eq!(
            json,
            serde_json::json!({
                "name": "worker",
                "manifest": {
                    "mode": "exact",
                    "manifest": {
                        "url": "https://example.com/worker.json5"
                    }
                },
                "config": {
                    "mode": {
                        "state": "prefilled",
                        "value": "batch"
                    },
                    "count": {
                        "state": "open",
                        "required": true
                    }
                },
                "bindings": {
                    "db": {
                        "state": "prefilled",
                        "selector": "slots.db"
                    },
                    "seed": {
                        "state": "open",
                        "optional": false,
                        "compatible_kind": "url",
                        "candidates": [
                            "provides.api",
                            "children.prev-job.exports.result"
                        ]
                    }
                },
                "exports": {
                    "visible": ["result"]
                },
                "limits": {
                    "max_live_children": 64
                },
                "possible_backends": ["compose"]
            })
        );
    }

    #[test]
    fn create_child_exact_request_and_response_match_design_fixture() {
        let request = CreateChildRequest {
            template: "worker".to_string(),
            name: "job-1".to_string(),
            manifest: None,
            config: BTreeMap::from([("count".to_string(), serde_json::json!(5))]),
            bindings: BTreeMap::from([(
                "seed".to_string(),
                BindingInput {
                    selector: Some("provides.api".to_string()),
                    handle: None,
                },
            )]),
        };
        let response = CreateChildResponse {
            child: ChildHandle {
                name: "job-1".to_string(),
                selector: "children.job-1".to_string(),
            },
            outputs: BTreeMap::from([(
                "result".to_string(),
                OutputHandle {
                    selector: "children.job-1.exports.result".to_string(),
                    handle: Some("h_01HV".to_string()),
                },
            )]),
        };

        assert_eq!(
            serde_json::to_value(&request).expect("serialize create request"),
            serde_json::json!({
                "template": "worker",
                "name": "job-1",
                "config": {
                    "count": 5
                },
                "bindings": {
                    "seed": {
                        "selector": "provides.api"
                    }
                }
            })
        );
        assert_eq!(
            serde_json::to_value(&response).expect("serialize create response"),
            serde_json::json!({
                "child": {
                    "name": "job-1",
                    "selector": "children.job-1"
                },
                "outputs": {
                    "result": {
                        "selector": "children.job-1.exports.result",
                        "handle": "h_01HV"
                    }
                }
            })
        );
    }

    #[test]
    fn create_child_open_request_matches_design_fixture() {
        let request = CreateChildRequest {
            template: "arbitrary_job".to_string(),
            name: "job-2".to_string(),
            manifest: Some(
                "https://example.com/jobs/reporter.json5"
                    .parse()
                    .expect("manifest ref"),
            ),
            config: BTreeMap::new(),
            bindings: BTreeMap::from([(
                "input".to_string(),
                BindingInput {
                    selector: Some("children.prev-job.exports.result".to_string()),
                    handle: None,
                },
            )]),
        };

        assert_eq!(
            serde_json::to_value(&request).expect("serialize open create request"),
            serde_json::json!({
                "template": "arbitrary_job",
                "name": "job-2",
                "manifest": "https://example.com/jobs/reporter.json5",
                "bindings": {
                    "input": {
                        "selector": "children.prev-job.exports.result"
                    }
                }
            })
        );
    }

    #[test]
    fn template_resolve_request_matches_design_fixture() {
        let request = TemplateResolveRequest {
            manifest: Some(
                "https://example.com/jobs/reporter.json5"
                    .parse()
                    .expect("manifest ref"),
            ),
        };

        assert_eq!(
            serde_json::to_value(&request).expect("serialize resolve request"),
            serde_json::json!({
                "manifest": "https://example.com/jobs/reporter.json5"
            })
        );
    }

    #[test]
    fn snapshot_and_error_responses_match_design_fixture() {
        let snapshot = SnapshotResponse {
            scenario: serde_json::json!({ "version": "5" }),
            placement: serde_json::json!({ "sites": {} }),
        };
        let error = ProtocolErrorResponse {
            code: ProtocolErrorCode::NameConflict,
            message: "child 'job-1' already exists".to_string(),
            details: Some(serde_json::json!({ "child": "job-1" })),
        };

        assert_eq!(
            serde_json::to_value(&snapshot).expect("serialize snapshot response"),
            serde_json::json!({
                "scenario": { "version": "5" },
                "placement": { "sites": {} }
            })
        );
        assert_eq!(
            serde_json::to_value(&error).expect("serialize protocol error"),
            serde_json::json!({
                "code": "name_conflict",
                "message": "child 'job-1' already exists",
                "details": {
                    "child": "job-1"
                }
            })
        );
    }
}
