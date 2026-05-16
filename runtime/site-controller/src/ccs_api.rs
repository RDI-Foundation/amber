use super::{api::*, state::FrameworkControlState, *};

pub(crate) enum FrameworkComponentInspectRequest {
    ListTemplates,
    GetTemplate {
        template: String,
    },
    ResolveTemplate {
        template: String,
        request: TemplateResolveRequest,
    },
    ListChildren,
    GetChild {
        child: String,
    },
    GetSnapshot,
}

pub(crate) enum FrameworkComponentInspectResponse {
    ListTemplates(TemplateListResponse),
    GetTemplate(TemplateDescribeResponse),
    ResolveTemplate(TemplateDescribeResponse),
    ListChildren(ChildListResponse),
    GetChild(ChildDescribeResponse),
    GetSnapshot(SnapshotResponse),
}

pub(crate) enum FrameworkComponentMutateRequest {
    CreateChild(CreateChildRequest),
    DestroyChild { child: String },
}

pub(crate) enum FrameworkComponentMutateResponse {
    CreateChild(CreateChildResponse),
    DestroyChild(DestroyChildResponse),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct DestroyChildResponse {
    pub(crate) child: String,
    pub(crate) destroyed: bool,
}

pub(crate) async fn execute_framework_component_inspect(
    state: &FrameworkControlState,
    authority_realm_id: usize,
    request: FrameworkComponentInspectRequest,
) -> std::result::Result<FrameworkComponentInspectResponse, ProtocolErrorResponse> {
    Ok(match request {
        FrameworkComponentInspectRequest::ListTemplates => {
            FrameworkComponentInspectResponse::ListTemplates(list_templates(
                state,
                authority_realm_id,
            )?)
        }
        FrameworkComponentInspectRequest::GetTemplate { template } => {
            FrameworkComponentInspectResponse::GetTemplate(describe_template(
                state,
                authority_realm_id,
                &template,
            )?)
        }
        FrameworkComponentInspectRequest::ResolveTemplate { template, request } => {
            FrameworkComponentInspectResponse::ResolveTemplate(
                resolve_template(state, authority_realm_id, &template, request).await?,
            )
        }
        FrameworkComponentInspectRequest::ListChildren => {
            FrameworkComponentInspectResponse::ListChildren(list_children(
                state,
                authority_realm_id,
            ))
        }
        FrameworkComponentInspectRequest::GetChild { child } => {
            FrameworkComponentInspectResponse::GetChild(describe_child(
                state,
                authority_realm_id,
                &child,
            )?)
        }
        FrameworkComponentInspectRequest::GetSnapshot => {
            FrameworkComponentInspectResponse::GetSnapshot(snapshot(state, authority_realm_id)?)
        }
    })
}
