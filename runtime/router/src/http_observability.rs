use super::*;

const DEFAULT_HTTP_BODY_CAPTURE_LIMIT_BYTES: usize = 256 * 1024;
pub(super) const DEFAULT_HTTP_SSE_EVENT_CAPTURE_LIMIT_BYTES: usize = 64 * 1024;

// We keep local HeaderMap adapters because opentelemetry-http currently uses
// `http` 0.2 while the router stack uses `http` 1.x.
struct HeaderMapExtractor<'a>(&'a HeaderMap);

impl opentelemetry::propagation::Extractor for HeaderMapExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|name| name.as_str()).collect()
    }
}

struct HeaderMapInjector<'a>(&'a mut HeaderMap);

impl opentelemetry::propagation::Injector for HeaderMapInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes())
            && let Ok(value) = HeaderValue::from_str(&value)
        {
            self.0.insert(name, value);
        }
    }
}

pub(super) fn start_http_exchange_span(
    telemetry: &HttpExchangeTelemetryContext,
    req: &Request<Incoming>,
) -> tracing::Span {
    let parent_context = opentelemetry::global::get_text_map_propagator(|prop| {
        prop.extract(&HeaderMapExtractor(req.headers()))
    });
    let span_name = telemetry.span_name(req);

    let span = tracing::info_span!(
        "amber.binding",
        otel.name = span_name.as_str(),
        otel.kind = telemetry.otel_kind,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
        amber_entity_kind = "binding",
        amber_edge_kind = telemetry.edge_kind(),
        amber_edge_ref = telemetry.edge_ref(),
        amber_source_ref = telemetry.source_ref(),
        amber_source_component = telemetry.source_component(),
        amber_source_endpoint = telemetry.source_endpoint(),
        amber_destination_ref = telemetry.destination_ref(),
        amber_destination_component = telemetry.destination_component(),
        amber_destination_endpoint = telemetry.destination_endpoint(),
        amber_flow = telemetry.flow_name,
        amber_local_role = telemetry.local_role(),
        amber_peer_role = telemetry.peer_role(),
        amber_transport = "http",
        amber_exchange_id = tracing::field::Empty,
        amber_trace_id = tracing::field::Empty,
        amber_application_error = tracing::field::Empty,
        amber_protocol = tracing::field::Empty,
        amber_rpc_kind = tracing::field::Empty,
        amber_rpc_method = tracing::field::Empty,
        amber_request_key = tracing::field::Empty,
        amber_rpc_id = tracing::field::Empty,
        amber_capability = telemetry.capability.as_ref(),
        amber_slot = telemetry.slot(),
        amber_capability_kind = telemetry.capability_kind(),
        amber_capability_profile = telemetry.capability_profile(),
        "http.request.method" = %req.method(),
        "url.path" = %req.uri().path(),
        "http.response.status_code" = tracing::field::Empty,
        http_method = %req.method(),
        http_path = %req.uri().path(),
        http_status_code = tracing::field::Empty,
    );
    let _ = span.set_parent(parent_context);
    record_exchange_identity(&span);
    span
}

pub(super) fn inject_trace_context(span: &tracing::Span, headers: &mut HeaderMap) {
    let context = span.context();
    opentelemetry::global::get_text_map_propagator(|prop| {
        prop.inject_context(&context, &mut HeaderMapInjector(headers))
    });
}

fn current_exchange_ids(span: &tracing::Span) -> (String, String) {
    let span_context = span.context().span().span_context().clone();
    if span_context.is_valid() {
        (
            span_context.trace_id().to_string(),
            span_context.span_id().to_string(),
        )
    } else {
        (String::new(), String::new())
    }
}

fn record_exchange_identity(span: &tracing::Span) {
    let (trace_id, exchange_id) = current_exchange_ids(span);
    if !trace_id.is_empty() {
        span.record("amber_trace_id", trace_id.as_str());
    }
    if !exchange_id.is_empty() {
        span.record("amber_exchange_id", exchange_id.as_str());
    }
}

fn record_http_status(span: &tracing::Span, status: StatusCode, application_error: bool) {
    let status_code = status.as_u16();
    span.record("http_status_code", status_code);
    span.record("http.response.status_code", status_code);
    span.record(
        "otel.status_code",
        if application_error || status.as_u16() >= 500 {
            "error"
        } else {
            otel_status_code_for_http(status)
        },
    );
}

pub(super) fn finalize_http_exchange_response(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    response: Response<BoxBody>,
) -> Response<BoxBody> {
    let status = response.status();
    let summary = telemetry.summary_snapshot();
    record_http_status(span, status, summary.has_application_error());
    if let Some(message) = summary.application_error_message() {
        span.record("otel.status_description", message.as_str());
    } else if status.is_server_error() {
        span.record(
            "otel.status_description",
            status.canonical_reason().unwrap_or("server error"),
        );
    }
    response
}

pub(super) fn otel_status_code_for_http(status: StatusCode) -> &'static str {
    if status.as_u16() >= 500 {
        "error"
    } else {
        "ok"
    }
}

fn headers_to_json(headers: &HeaderMap) -> String {
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        values
            .entry(name.as_str().to_string())
            .or_default()
            .push(String::from_utf8_lossy(value.as_bytes()).into_owned());
    }
    serde_json::to_string(&values).unwrap_or_else(|_| "{}".to_string())
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct ProtocolSummary {
    protocol: Option<&'static str>,
    rpc_kind: Option<&'static str>,
    rpc_method_raw: Option<String>,
    rpc_method: Option<String>,
    rpc_id: Option<String>,
    rpc_is_notification: Option<bool>,
    rpc_error_code: Option<i64>,
    rpc_error_message: Option<String>,
    request_key: Option<String>,
    parent_request_key: Option<String>,
    mcp_tool_name: Option<String>,
    mcp_task_id: Option<String>,
    mcp_progress_token: Option<String>,
    mcp_progress: Option<f64>,
    mcp_progress_total: Option<f64>,
    mcp_progress_message: Option<String>,
    mcp_resource_uri: Option<String>,
    mcp_cursor: Option<String>,
    mcp_next_cursor: Option<String>,
    mcp_list_changed: Option<bool>,
    mcp_tool_is_error: Option<bool>,
    mcp_log_level: Option<String>,
    mcp_logger: Option<String>,
    a2a_message_id: Option<String>,
    a2a_task_id: Option<String>,
    a2a_context_id: Option<String>,
    a2a_reference_task_id: Option<String>,
    a2a_task_state: Option<String>,
    a2a_artifact_count: Option<i64>,
}

impl ProtocolSummary {
    pub(super) fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    pub(super) fn merge_from(&mut self, other: &Self) {
        macro_rules! merge_field {
            ($field:ident) => {
                if other.$field.is_some() {
                    self.$field = other.$field.clone();
                }
            };
        }

        merge_field!(protocol);
        merge_field!(rpc_kind);
        merge_field!(rpc_method_raw);
        merge_field!(rpc_method);
        merge_field!(rpc_id);
        merge_field!(rpc_is_notification);
        merge_field!(rpc_error_code);
        merge_field!(rpc_error_message);
        merge_field!(request_key);
        merge_field!(parent_request_key);
        merge_field!(mcp_tool_name);
        merge_field!(mcp_task_id);
        merge_field!(mcp_progress_token);
        merge_field!(mcp_progress);
        merge_field!(mcp_progress_total);
        merge_field!(mcp_progress_message);
        merge_field!(mcp_resource_uri);
        merge_field!(mcp_cursor);
        merge_field!(mcp_next_cursor);
        merge_field!(mcp_list_changed);
        merge_field!(mcp_tool_is_error);
        merge_field!(mcp_log_level);
        merge_field!(mcp_logger);
        merge_field!(a2a_message_id);
        merge_field!(a2a_task_id);
        merge_field!(a2a_context_id);
        merge_field!(a2a_reference_task_id);
        merge_field!(a2a_task_state);
        merge_field!(a2a_artifact_count);
    }

    fn has_application_error(&self) -> bool {
        self.rpc_error_code.is_some()
            || self.mcp_tool_is_error == Some(true)
            || self
                .a2a_task_state
                .as_deref()
                .is_some_and(|state| state.eq_ignore_ascii_case("TASK_STATE_FAILED"))
    }

    fn application_error_message(&self) -> Option<String> {
        self.rpc_error_message
            .clone()
            .or_else(|| {
                self.rpc_error_code
                    .map(|code| format!("json-rpc error {code}"))
            })
            .or_else(|| {
                (self.mcp_tool_is_error == Some(true))
                    .then_some("tool call returned isError=true".to_string())
            })
            .or_else(|| {
                self.a2a_task_state.as_ref().and_then(|state| {
                    state
                        .eq_ignore_ascii_case("TASK_STATE_FAILED")
                        .then_some(format!("a2a task ended in {state}"))
                })
            })
    }
}

pub(super) fn exchange_message(
    telemetry: &HttpExchangeTelemetryContext,
    part: HttpLifecyclePart,
    summary: &ProtocolSummary,
) -> String {
    let source_component = telemetry.source_component();
    let destination_component = telemetry.destination_component();
    let edge_ref = telemetry.edge_ref();
    let base = match telemetry.edge_kind {
        HttpEdgeKind::Export => match part {
            HttpLifecyclePart::Request => format!(
                "request received from {} by {}",
                telemetry.source_ref(),
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                }
            ),
            HttpLifecyclePart::Response => format!(
                "response sent from {} to {}",
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                },
                telemetry.source_ref(),
            ),
        },
        HttpEdgeKind::ExternalSlot => match part {
            HttpLifecyclePart::Request => format!(
                "request sent from {} to external slot {} via {}",
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                telemetry.destination_endpoint(),
                edge_ref,
            ),
            HttpLifecyclePart::Response => format!(
                "response received by {} from external slot {} via {}",
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                telemetry.destination_endpoint(),
                edge_ref,
            ),
        },
        HttpEdgeKind::Binding => match (telemetry.flow, part) {
            (RewriteFlow::Outbound, HttpLifecyclePart::Request) => format!(
                "request sent from {} to {} via {}",
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                },
                edge_ref,
            ),
            (RewriteFlow::Inbound, HttpLifecyclePart::Request) => format!(
                "request received by {} from {} via {}",
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                },
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                edge_ref,
            ),
            (RewriteFlow::Inbound, HttpLifecyclePart::Response) => format!(
                "response sent from {} to {} via {}",
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                },
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                edge_ref,
            ),
            (RewriteFlow::Outbound, HttpLifecyclePart::Response) => format!(
                "response received by {} from {} via {}",
                if source_component.is_empty() {
                    telemetry.source_ref()
                } else {
                    source_component
                },
                if destination_component.is_empty() {
                    telemetry.destination_ref()
                } else {
                    destination_component
                },
                edge_ref,
            ),
        },
    };
    match protocol_detail(telemetry, summary, part) {
        Some(detail) => format!("{base}: {detail}"),
        None => base,
    }
}

pub(super) fn emit_binding_failure_event(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    status: StatusCode,
    reason: &str,
    error_detail: Option<String>,
) {
    let summary = telemetry.summary_snapshot();
    let mut message = exchange_message(telemetry, HttpLifecyclePart::Request, &summary);
    message.push_str(" failed");
    if !reason.is_empty() {
        message.push_str(": ");
        message.push_str(reason);
    }

    let mut extra_attributes = Vec::with_capacity(2);
    push_log_attr(
        &mut extra_attributes,
        "http.response.status_code",
        i64::from(status.as_u16()),
    );
    if let Some(error_detail) = error_detail {
        push_nonempty_log_attr(
            &mut extra_attributes,
            "error.message",
            error_detail.as_str(),
        );
    }
    emit_binding_log(
        span,
        telemetry,
        &summary,
        BindingLogSpec {
            level: Severity::Warn,
            part: HttpLifecyclePart::Response,
            step: "error",
            transport: "http",
            event_name: "amber.binding.error",
            message,
            extra_attributes,
        },
    );
}

pub(super) fn protocol_detail(
    telemetry: &HttpExchangeTelemetryContext,
    summary: &ProtocolSummary,
    part: HttpLifecyclePart,
) -> Option<String> {
    let mut narrative = protocol_narrative(telemetry, summary, part)?;
    if part == HttpLifecyclePart::Request && summary.rpc_is_notification == Some(true) {
        narrative.text.push_str(" notification");
    }
    if part == HttpLifecyclePart::Response && narrative.append_response_suffix {
        if let Some(code) = summary.rpc_error_code {
            narrative.text.push_str(&format!(" error {code}"));
        } else if summary.has_application_error() {
            narrative.text.push_str(" error");
        } else if summary.rpc_kind == Some("result") {
            narrative.text.push_str(" result");
        } else {
            narrative.text.push_str(" response");
        }
    }
    if let Some(id) = summary.rpc_id.as_deref().filter(|id| !id.is_empty()) {
        narrative
            .text
            .push_str(&format!(" (id={})", compact_display_value(id, 20)));
    }
    Some(narrative.text)
}

struct ProtocolNarrative {
    text: String,
    append_response_suffix: bool,
}

impl ProtocolNarrative {
    fn new(text: String, append_response_suffix: bool) -> Self {
        Self {
            text,
            append_response_suffix,
        }
    }
}

fn protocol_narrative(
    telemetry: &HttpExchangeTelemetryContext,
    summary: &ProtocolSummary,
    part: HttpLifecyclePart,
) -> Option<ProtocolNarrative> {
    if let Some(detail) = a2a_task_update_detail(summary) {
        return Some(ProtocolNarrative::new(detail, false));
    }
    if let Some(detail) = mcp_progress_detail(summary) {
        return Some(ProtocolNarrative::new(detail, false));
    }
    if let Some(detail) = mcp_log_message_detail(summary) {
        return Some(ProtocolNarrative::new(detail, false));
    }
    if let Some(detail) = protocol_operation_detail(summary) {
        return Some(ProtocolNarrative::new(detail, true));
    }
    if part == HttpLifecyclePart::Response {
        let remembered = telemetry.summary_snapshot();
        if remembered != *summary
            && let Some(detail) = protocol_narrative(telemetry, &remembered, part)
        {
            return Some(detail);
        }
    }
    telemetry
        .http_subject()
        .map(|subject| ProtocolNarrative::new(subject.to_string(), false))
}

fn a2a_task_update_detail(summary: &ProtocolSummary) -> Option<String> {
    let state = summary.a2a_task_state.as_deref()?;
    let mut detail = format!("task {}", humanize_task_state(state));
    if let Some(count) = summary.a2a_artifact_count.filter(|count| *count > 0) {
        let noun = if count == 1 { "artifact" } else { "artifacts" };
        detail.push_str(&format!(" ({count} {noun})"));
    }
    Some(detail)
}

fn mcp_progress_detail(summary: &ProtocolSummary) -> Option<String> {
    let progress = summary.mcp_progress?;
    let mut detail = if let Some(total) = summary.mcp_progress_total {
        format!(
            "progress {}/{}",
            format_decimal(progress),
            format_decimal(total)
        )
    } else {
        format!("progress {}", format_decimal(progress))
    };
    if let Some(message) = summary
        .mcp_progress_message
        .as_deref()
        .filter(|message| !message.is_empty())
    {
        detail.push_str(&format!(" ({})", compact_display_value(message, 28)));
    }
    Some(detail)
}

fn mcp_log_message_detail(summary: &ProtocolSummary) -> Option<String> {
    if summary.rpc_method.as_deref() != Some("notifications/message") {
        return None;
    }
    summary.mcp_log_level.as_deref().map(|level| {
        let mut detail = format!("log {}", humanize_identifier(level));
        if let Some(logger) = summary
            .mcp_logger
            .as_deref()
            .filter(|logger| !logger.is_empty())
        {
            detail.push_str(&format!(" {}", compact_display_value(logger, 20)));
        }
        detail
    })
}

fn protocol_operation_detail(summary: &ProtocolSummary) -> Option<String> {
    let method = summary
        .rpc_method
        .as_deref()
        .or(summary.rpc_method_raw.as_deref())?;
    let mut detail = humanize_method_detail(method);

    if let Some(tool_name) = summary
        .mcp_tool_name
        .as_deref()
        .filter(|_| method == "tools/call")
    {
        detail.push_str(&format!(" {}", compact_display_value(tool_name, 24)));
    } else if let Some(resource_uri) = summary
        .mcp_resource_uri
        .as_deref()
        .filter(|_| method.starts_with("resources/"))
    {
        detail.push_str(&format!(" {}", compact_display_value(resource_uri, 32)));
    }

    Some(detail)
}

fn humanize_method_detail(method: &str) -> String {
    if let Some((family, action)) = method.split_once('/') {
        return humanize_slash_method(family, action);
    }
    humanize_identifier(method)
}

fn humanize_slash_method(family: &str, action: &str) -> String {
    let action = humanize_identifier(action);
    let family_plural = humanize_identifier(family);
    let family_singular = singularize_phrase(&family_plural);

    if family == "notifications" {
        return match action.as_str() {
            "progress" => "progress update".to_string(),
            "message" => "log message".to_string(),
            _ => format!("{action} notification"),
        };
    }

    if action == "list" {
        return format!("list {family_plural}");
    }

    format!("{action} {family_singular}")
}

fn singularize_phrase(phrase: &str) -> String {
    let Some((prefix, last)) = phrase.rsplit_once(' ') else {
        return singularize_word(phrase).to_string();
    };
    format!("{prefix} {}", singularize_word(last))
}

fn singularize_word(word: &str) -> &str {
    if word.len() > 1 && word.ends_with('s') {
        &word[..word.len() - 1]
    } else {
        word
    }
}

fn humanize_task_state(state: &str) -> String {
    humanize_identifier(state.trim_start_matches("TASK_STATE_"))
}

fn format_decimal(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{}", value as i64)
    } else {
        format!("{value:.2}")
    }
}

fn compact_display_value(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 6 {
        return value.chars().take(max_chars).collect();
    }
    let left = (max_chars - 3) / 2;
    let right = max_chars - 3 - left;
    let prefix = value.chars().take(left).collect::<String>();
    let suffix = value
        .chars()
        .rev()
        .take(right)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{prefix}...{suffix}")
}

fn humanize_identifier(input: &str) -> String {
    let chars = input.chars().collect::<Vec<_>>();
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_was_lower_or_digit = false;
    let mut previous_was_upper = false;

    for (index, ch) in chars.iter().enumerate() {
        if !ch.is_ascii_alphanumeric() {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous_was_lower_or_digit = false;
            previous_was_upper = false;
            continue;
        }

        let next_is_lower = chars
            .get(index + 1)
            .is_some_and(|next| next.is_ascii_lowercase());
        let starts_new_word = !current.is_empty()
            && ((previous_was_lower_or_digit && ch.is_ascii_uppercase())
                || (previous_was_upper && ch.is_ascii_uppercase() && next_is_lower));
        if starts_new_word {
            words.push(std::mem::take(&mut current));
        }

        current.push(ch.to_ascii_lowercase());
        previous_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        previous_was_upper = ch.is_ascii_uppercase();
    }

    if !current.is_empty() {
        words.push(current);
    }

    words.join(" ")
}

pub(super) fn http_subject_from_path(path: &str) -> Option<String> {
    let segment = path
        .split('?')
        .next()
        .unwrap_or(path)
        .rsplit('/')
        .find(|segment| !segment.is_empty())?;
    let stem = segment
        .split('.')
        .next()
        .unwrap_or(segment)
        .trim_matches('.');
    let subject = humanize_identifier(stem);
    (!subject.is_empty() && subject.chars().any(|ch| ch.is_ascii_alphabetic())).then_some(subject)
}

#[derive(Clone, Debug, Default)]
pub(super) struct JsonRpcExtraction {
    pub(super) kind: Option<&'static str>,
    pub(super) method_raw: Option<String>,
    pub(super) method: Option<String>,
    pub(super) id: Option<String>,
    pub(super) is_notification: Option<bool>,
    pub(super) error_code: Option<i64>,
    pub(super) error_message: Option<String>,
}

#[derive(Clone, Copy)]
struct EventProtocolFields<'a> {
    protocol: &'a str,
    rpc_kind: &'a str,
    request_key: &'a str,
    rpc_id: &'a str,
    rpc_method: &'a str,
    application_error: bool,
}

fn protocol_fields(summary: &ProtocolSummary) -> EventProtocolFields<'_> {
    EventProtocolFields {
        protocol: summary.protocol.unwrap_or(""),
        rpc_kind: summary.rpc_kind.unwrap_or(""),
        request_key: summary.request_key.as_deref().unwrap_or(""),
        rpc_id: summary.rpc_id.as_deref().unwrap_or(""),
        rpc_method: summary.rpc_method.as_deref().unwrap_or(""),
        application_error: summary.has_application_error(),
    }
}

fn push_protocol_summary_log_attrs(
    attributes: &mut OtlpLogAttributes,
    telemetry: &HttpExchangeTelemetryContext,
    summary: &ProtocolSummary,
) {
    push_nonempty_log_attr(
        attributes,
        "amber_http_subject",
        telemetry.http_subject().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_parent_request_key",
        summary.parent_request_key.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_mcp_tool_name",
        summary.mcp_tool_name.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_mcp_task_id",
        summary.mcp_task_id.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_mcp_progress_token",
        summary.mcp_progress_token.as_deref().unwrap_or(""),
    );
    if let Some(progress) = summary.mcp_progress {
        push_log_attr(attributes, "amber_mcp_progress", progress);
    }
    if let Some(total) = summary.mcp_progress_total {
        push_log_attr(attributes, "amber_mcp_progress_total", total);
    }
    push_nonempty_log_attr(
        attributes,
        "amber_mcp_progress_message",
        summary.mcp_progress_message.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_mcp_resource_uri",
        summary.mcp_resource_uri.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_mcp_cursor",
        summary.mcp_cursor.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_mcp_next_cursor",
        summary.mcp_next_cursor.as_deref().unwrap_or(""),
    );
    if let Some(list_changed) = summary.mcp_list_changed {
        push_log_attr(attributes, "amber_mcp_list_changed", list_changed);
    }
    if let Some(tool_is_error) = summary.mcp_tool_is_error {
        push_log_attr(attributes, "amber_mcp_tool_is_error", tool_is_error);
    }
    push_nonempty_log_attr(
        attributes,
        "amber_mcp_log_level",
        summary.mcp_log_level.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_mcp_logger",
        summary.mcp_logger.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_a2a_message_id",
        summary.a2a_message_id.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_a2a_task_id",
        summary.a2a_task_id.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_a2a_context_id",
        summary.a2a_context_id.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_a2a_reference_task_id",
        summary.a2a_reference_task_id.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        attributes,
        "amber_a2a_task_state",
        summary.a2a_task_state.as_deref().unwrap_or(""),
    );
    if let Some(artifact_count) = summary.a2a_artifact_count {
        push_log_attr(attributes, "amber_a2a_artifact_count", artifact_count);
    }
}

fn record_protocol_summary(span: &tracing::Span, summary: &ProtocolSummary) {
    if let Some(protocol) = summary.protocol {
        span.record("amber_protocol", protocol);
    }
    if let Some(kind) = summary.rpc_kind {
        span.record("amber_rpc_kind", kind);
    }
    if let Some(method) = summary.rpc_method.as_deref() {
        span.record("amber_rpc_method", method);
    }
    if let Some(request_key) = summary.request_key.as_deref() {
        span.record("amber_request_key", request_key);
    }
    if let Some(rpc_id) = summary.rpc_id.as_deref() {
        span.record("amber_rpc_id", rpc_id);
    }
    if summary.has_application_error() {
        span.record("amber_application_error", true);
        span.record("otel.status_code", "error");
        if let Some(message) = summary.application_error_message() {
            span.record("otel.status_description", message.as_str());
        }
    }
}

type OtlpLogAttributes = Vec<(Key, AnyValue)>;

struct BindingLogSpec {
    level: Severity,
    part: HttpLifecyclePart,
    step: &'static str,
    transport: &'static str,
    event_name: &'static str,
    message: String,
    extra_attributes: OtlpLogAttributes,
}

fn push_log_attr<V>(attributes: &mut OtlpLogAttributes, key: &'static str, value: V)
where
    V: Into<AnyValue>,
{
    attributes.push((Key::new(key), value.into()));
}

fn push_nonempty_log_attr(attributes: &mut OtlpLogAttributes, key: &'static str, value: &str) {
    if !value.is_empty() {
        push_log_attr(attributes, key, value.to_string());
    }
}

fn push_true_log_attr(attributes: &mut OtlpLogAttributes, key: &'static str, value: bool) {
    if value {
        push_log_attr(attributes, key, value);
    }
}

fn binding_log_trace_context(span: &tracing::Span) -> Option<OtlpTraceContext> {
    let span_context = span.context().span().span_context().clone();
    span_context.is_valid().then_some(OtlpTraceContext {
        trace_id: span_context.trace_id(),
        span_id: span_context.span_id(),
        trace_flags: Some(span_context.trace_flags()),
    })
}

fn binding_log_attributes(
    telemetry: &HttpExchangeTelemetryContext,
    summary: &ProtocolSummary,
    trace_id: &str,
    exchange_id: &str,
    spec: &mut BindingLogSpec,
) -> OtlpLogAttributes {
    let fields = protocol_fields(summary);
    let mut attributes = Vec::with_capacity(24 + spec.extra_attributes.len());

    push_log_attr(&mut attributes, "amber_entity_kind", "binding");
    push_log_attr(&mut attributes, "amber_edge_kind", telemetry.edge_kind());
    push_nonempty_log_attr(&mut attributes, "amber_edge_ref", telemetry.edge_ref());
    push_nonempty_log_attr(&mut attributes, "amber_source_ref", telemetry.source_ref());
    push_nonempty_log_attr(
        &mut attributes,
        "amber_source_component",
        telemetry.source_component(),
    );
    push_nonempty_log_attr(
        &mut attributes,
        "amber_source_endpoint",
        telemetry.source_endpoint(),
    );
    push_nonempty_log_attr(
        &mut attributes,
        "amber_destination_ref",
        telemetry.destination_ref(),
    );
    push_nonempty_log_attr(
        &mut attributes,
        "amber_destination_component",
        telemetry.destination_component(),
    );
    push_nonempty_log_attr(
        &mut attributes,
        "amber_destination_endpoint",
        telemetry.destination_endpoint(),
    );
    push_log_attr(&mut attributes, "amber_flow", telemetry.flow_name);
    push_log_attr(&mut attributes, "amber_local_role", telemetry.local_role());
    push_log_attr(&mut attributes, "amber_peer_role", telemetry.peer_role());
    push_log_attr(
        &mut attributes,
        "amber_lifecycle_stage",
        telemetry.lifecycle_stage(spec.part),
    );
    push_log_attr(&mut attributes, "amber_exchange_step", spec.step);
    push_log_attr(&mut attributes, "amber_transport", spec.transport);
    push_nonempty_log_attr(&mut attributes, "amber_trace_id", trace_id);
    push_nonempty_log_attr(&mut attributes, "amber_exchange_id", exchange_id);
    push_nonempty_log_attr(
        &mut attributes,
        "amber_capability",
        telemetry.capability.as_ref(),
    );
    push_nonempty_log_attr(&mut attributes, "amber_slot", telemetry.slot());
    push_nonempty_log_attr(
        &mut attributes,
        "amber_capability_kind",
        telemetry.capability_kind(),
    );
    push_nonempty_log_attr(
        &mut attributes,
        "amber_capability_profile",
        telemetry.capability_profile(),
    );
    push_nonempty_log_attr(&mut attributes, "amber_protocol", fields.protocol);
    push_nonempty_log_attr(&mut attributes, "amber_rpc_kind", fields.rpc_kind);
    push_nonempty_log_attr(&mut attributes, "amber_request_key", fields.request_key);
    push_nonempty_log_attr(&mut attributes, "amber_rpc_id", fields.rpc_id);
    push_nonempty_log_attr(&mut attributes, "amber_rpc_method", fields.rpc_method);
    push_protocol_summary_log_attrs(&mut attributes, telemetry, summary);
    push_true_log_attr(
        &mut attributes,
        "amber_application_error",
        fields.application_error,
    );
    push_log_attr(&mut attributes, "event", spec.event_name);
    attributes.append(&mut spec.extra_attributes);
    attributes
}

fn emit_binding_console_log(level: Severity, span: &tracing::Span, message: &str) {
    span.in_scope(|| match level {
        Severity::Warn
        | Severity::Warn2
        | Severity::Warn3
        | Severity::Warn4
        | Severity::Error
        | Severity::Error2
        | Severity::Error3
        | Severity::Error4
        | Severity::Fatal
        | Severity::Fatal2
        | Severity::Fatal3
        | Severity::Fatal4 => tracing::warn!(target: "amber.binding", "{message}"),
        _ => tracing::info!(target: "amber.binding", "{message}"),
    });
}

fn emit_binding_log(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    summary: &ProtocolSummary,
    mut spec: BindingLogSpec,
) {
    telemetry.remember_summary(summary);
    record_protocol_summary(span, summary);
    let (trace_id, exchange_id) = current_exchange_ids(span);

    emit_binding_console_log(spec.level, span, &spec.message);
    emit_otlp_log(OtlpLogMessage {
        scope_name: "amber.binding",
        target: "amber.binding",
        event_name: spec.event_name,
        severity: spec.level,
        body: spec.message.clone(),
        attributes: binding_log_attributes(
            telemetry,
            summary,
            trace_id.as_str(),
            exchange_id.as_str(),
            &mut spec,
        ),
        trace_context: binding_log_trace_context(span),
    });
}

pub(super) fn emit_headers_event(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    part: HttpLifecyclePart,
    event_name: &'static str,
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    headers: &HeaderMap,
) {
    let headers_json = headers_to_json(headers);
    let summary = telemetry.summary_snapshot();
    let message = format!("{} [headers]", exchange_message(telemetry, part, &summary));
    let mut extra_attributes = Vec::with_capacity(3);
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_headers_json",
        headers_json.as_str(),
    );
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_body_content_type",
        content_type.unwrap_or(""),
    );
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_body_content_encoding",
        content_encoding.unwrap_or(""),
    );
    emit_binding_log(
        span,
        telemetry,
        &summary,
        BindingLogSpec {
            level: Severity::Info,
            part,
            step: "headers",
            transport: "http",
            event_name,
            message,
            extra_attributes,
        },
    );
}

#[cfg(test)]
pub(super) fn extract_json_rpc_from_text(body_text: &str) -> JsonRpcExtraction {
    if body_text.trim().is_empty() {
        return JsonRpcExtraction::default();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body_text) else {
        return JsonRpcExtraction::default();
    };
    extract_json_rpc_from_value(&value)
}

fn extract_json_rpc_from_value(value: &serde_json::Value) -> JsonRpcExtraction {
    match value {
        serde_json::Value::Object(_) => extract_json_rpc_from_object(value),
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|item| {
                let extracted = extract_json_rpc_from_object(item);
                (extracted.method.is_some()
                    || extracted.id.is_some()
                    || extracted.error_code.is_some()
                    || extracted.kind.is_some())
                .then_some(extracted)
            })
            .unwrap_or_default(),
        _ => JsonRpcExtraction::default(),
    }
}

fn extract_json_rpc_from_object(value: &serde_json::Value) -> JsonRpcExtraction {
    let Some(obj) = value.as_object() else {
        return JsonRpcExtraction::default();
    };
    if obj.get("jsonrpc").and_then(|jsonrpc| jsonrpc.as_str()) != Some("2.0") {
        return JsonRpcExtraction::default();
    }

    let method_raw = obj
        .get("method")
        .and_then(|value| value.as_str())
        .map(ToString::to_string);
    let method = method_raw.as_deref().map(normalize_json_rpc_method);
    let id = obj.get("id").and_then(json_rpc_id_to_string);
    let error = obj.get("error").and_then(|value| value.as_object());
    let error_code = error
        .and_then(|error| error.get("code"))
        .and_then(|code| code.as_i64());
    let error_message = error
        .and_then(|error| error.get("message"))
        .and_then(|message| message.as_str())
        .map(ToString::to_string);
    let kind = if error.is_some() {
        Some("error")
    } else if obj.get("result").is_some() {
        Some("result")
    } else if method_raw.is_some() {
        Some(if id.is_some() {
            "request"
        } else {
            "notification"
        })
    } else {
        None
    };

    JsonRpcExtraction {
        kind,
        method_raw,
        method,
        id,
        is_notification: kind.map(|value| value == "notification"),
        error_code,
        error_message,
    }
}

fn normalize_json_rpc_method(method: &str) -> String {
    match method {
        "message/send" => "SendMessage".to_string(),
        "message/stream" => "SendStreamingMessage".to_string(),
        _ => method.to_string(),
    }
}

fn json_rpc_id_to_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Null => Some("null".to_string()),
        _ => None,
    }
}

fn protocol_hint_for_exchange(
    telemetry: &HttpExchangeTelemetryContext,
    rpc: &JsonRpcExtraction,
) -> Option<&'static str> {
    match telemetry.capability_kind() {
        "mcp" => return Some("mcp"),
        "a2a" => return Some("a2a"),
        _ => {}
    }

    if rpc.method.as_deref().is_some_and(|method| {
        is_mcp_method(method) || is_mcp_method(rpc.method_raw.as_deref().unwrap_or(method))
    }) || rpc.method_raw.as_deref().is_some_and(is_mcp_method)
    {
        Some("mcp")
    } else if rpc.method.as_deref().is_some_and(is_a2a_method)
        || rpc.method_raw.as_deref().is_some_and(is_a2a_method)
    {
        Some("a2a")
    } else if rpc.kind.is_some() {
        Some("jsonrpc")
    } else {
        None
    }
}

fn is_mcp_method(method: &str) -> bool {
    matches!(method, "initialize" | "ping")
        || method.starts_with("completion/")
        || method.starts_with("elicitation/")
        || method.starts_with("logging/")
        || method.starts_with("notifications/")
        || method.starts_with("prompts/")
        || method.starts_with("resources/")
        || method.starts_with("roots/")
        || method.starts_with("sampling/")
        || method.starts_with("tasks/")
        || method.starts_with("tools/")
}

fn is_a2a_method(method: &str) -> bool {
    matches!(
        method,
        "CancelTask"
            | "GetExtendedAgentCard"
            | "GetTask"
            | "ListTasks"
            | "SendMessage"
            | "SendStreamingMessage"
            | "SubscribeToTask"
    )
}

fn first_json_rpc_object(
    value: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    match value {
        serde_json::Value::Object(obj) => Some(obj),
        serde_json::Value::Array(values) => values.iter().find_map(|item| item.as_object()),
        _ => None,
    }
}

fn json_string(value: Option<&serde_json::Value>) -> Option<String> {
    value.and_then(|value| match value {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        serde_json::Value::Bool(value) => Some(value.to_string()),
        serde_json::Value::Null => Some("null".to_string()),
        _ => None,
    })
}

fn json_f64(value: Option<&serde_json::Value>) -> Option<f64> {
    value.and_then(|value| match value {
        serde_json::Value::Number(value) => value.as_f64(),
        _ => None,
    })
}

fn extract_mcp_fields(value: &serde_json::Value, method: Option<&str>) -> ProtocolSummary {
    let Some(obj) = first_json_rpc_object(value) else {
        return ProtocolSummary::default();
    };
    let params = obj.get("params").and_then(|value| value.as_object());
    let result = obj.get("result").and_then(|value| value.as_object());

    let mut summary = ProtocolSummary {
        mcp_task_id: json_string(
            params
                .and_then(|value| value.get("taskId"))
                .or_else(|| result.and_then(|value| value.get("taskId")))
                .or_else(|| {
                    result
                        .and_then(|value| value.get("task"))
                        .and_then(|value| value.get("taskId"))
                })
                .or_else(|| {
                    result
                        .and_then(|value| value.get("task"))
                        .and_then(|value| value.get("id"))
                }),
        ),
        mcp_progress_token: json_string(params.and_then(|value| value.get("progressToken"))),
        mcp_cursor: json_string(params.and_then(|value| value.get("cursor"))),
        mcp_next_cursor: json_string(result.and_then(|value| value.get("nextCursor"))),
        mcp_list_changed: params
            .and_then(|value| value.get("listChanged"))
            .and_then(|value| value.as_bool())
            .or_else(|| {
                result
                    .and_then(|value| value.get("listChanged"))
                    .and_then(|value| value.as_bool())
            }),
        mcp_resource_uri: json_string(
            params
                .and_then(|value| value.get("uri"))
                .or_else(|| {
                    params
                        .and_then(|value| value.get("resource"))
                        .and_then(|value| value.get("uri"))
                })
                .or_else(|| result.and_then(|value| value.get("uri")))
                .or_else(|| {
                    result
                        .and_then(|value| value.get("contents"))
                        .and_then(|value| value.as_array())
                        .and_then(|value| value.first())
                        .and_then(|value| value.get("uri"))
                }),
        ),
        mcp_tool_is_error: result
            .and_then(|value| value.get("isError"))
            .and_then(|value| value.as_bool()),
        ..ProtocolSummary::default()
    };

    if matches!(method, Some("tools/call")) {
        summary.mcp_tool_name = json_string(params.and_then(|value| value.get("name")));
    }
    if matches!(method, Some("notifications/progress")) {
        summary.mcp_progress = json_f64(params.and_then(|value| value.get("progress")));
        summary.mcp_progress_total = json_f64(params.and_then(|value| value.get("total")));
        summary.mcp_progress_message = params
            .and_then(|value| value.get("message"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string);
    }
    if matches!(method, Some("notifications/message")) {
        summary.mcp_log_level = params
            .and_then(|value| value.get("level"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string);
        summary.mcp_logger = params
            .and_then(|value| value.get("logger"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string);
    }

    summary
}

fn extract_a2a_fields(value: &serde_json::Value) -> ProtocolSummary {
    let Some(obj) = first_json_rpc_object(value) else {
        return ProtocolSummary::default();
    };
    let params = obj.get("params").and_then(|value| value.as_object());
    let result = obj.get("result").and_then(|value| value.as_object());
    let request_message = params
        .and_then(|value| value.get("message"))
        .and_then(|value| value.as_object());
    let response_message = result
        .and_then(|value| value.get("message"))
        .and_then(|value| value.as_object());
    let task = result
        .and_then(|value| value.get("task"))
        .and_then(|value| value.as_object())
        .or_else(|| {
            params
                .and_then(|value| value.get("task"))
                .and_then(|value| value.as_object())
        });

    ProtocolSummary {
        a2a_message_id: request_message
            .and_then(|value| value.get("messageId"))
            .and_then(|value| value.as_str())
            .or_else(|| {
                response_message
                    .and_then(|value| value.get("messageId"))
                    .and_then(|value| value.as_str())
            })
            .map(ToString::to_string),
        a2a_context_id: request_message
            .and_then(|value| value.get("contextId"))
            .and_then(|value| value.as_str())
            .or_else(|| {
                response_message
                    .and_then(|value| value.get("contextId"))
                    .and_then(|value| value.as_str())
            })
            .or_else(|| {
                task.and_then(|value| value.get("contextId"))
                    .and_then(|value| value.as_str())
            })
            .map(ToString::to_string),
        a2a_reference_task_id: request_message
            .and_then(|value| value.get("referenceTaskIds"))
            .and_then(|value| value.as_array())
            .and_then(|value| value.first())
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        a2a_task_id: task
            .and_then(|value| value.get("id").or_else(|| value.get("taskId")))
            .and_then(|value| value.as_str())
            .or_else(|| {
                params
                    .and_then(|value| value.get("id").or_else(|| value.get("taskId")))
                    .and_then(|value| value.as_str())
            })
            .map(ToString::to_string),
        a2a_task_state: task
            .and_then(|value| value.get("status"))
            .and_then(|value| value.as_object())
            .and_then(|value| value.get("state"))
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
        a2a_artifact_count: task
            .and_then(|value| value.get("artifacts"))
            .and_then(|value| value.as_array())
            .map(|value| value.len() as i64),
        ..ProtocolSummary::default()
    }
}

pub(super) fn extract_protocol_summary(
    telemetry: &HttpExchangeTelemetryContext,
    body_text: &str,
) -> ProtocolSummary {
    if body_text.trim().is_empty() {
        return ProtocolSummary::default();
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(body_text) else {
        return ProtocolSummary::default();
    };

    let rpc = extract_json_rpc_from_value(&value);
    let mut summary = ProtocolSummary {
        protocol: protocol_hint_for_exchange(telemetry, &rpc),
        rpc_kind: rpc.kind,
        rpc_method_raw: rpc.method_raw.clone(),
        rpc_method: rpc.method.clone(),
        rpc_id: rpc.id.clone(),
        rpc_is_notification: rpc.is_notification,
        rpc_error_code: rpc.error_code,
        rpc_error_message: rpc.error_message.clone(),
        request_key: rpc.id.as_ref().map(|id| format!("rpc:{id}")),
        ..ProtocolSummary::default()
    };

    match summary.protocol {
        Some("mcp") => {
            summary.merge_from(&extract_mcp_fields(&value, summary.rpc_method.as_deref()))
        }
        Some("a2a") => summary.merge_from(&extract_a2a_fields(&value)),
        _ => {}
    }

    if summary.request_key.is_none() {
        if let Some(task_id) = summary.mcp_task_id.as_deref() {
            summary.request_key = Some(format!("mcp:task:{task_id}"));
        } else if let Some(task_id) = summary.a2a_task_id.as_deref() {
            summary.request_key = Some(format!("a2a:task:{task_id}"));
        } else if let Some(message_id) = summary.a2a_message_id.as_deref() {
            summary.request_key = Some(format!("a2a:message:{message_id}"));
        }
    }
    if summary.parent_request_key.is_none()
        && let Some(task_id) = summary.a2a_reference_task_id.as_deref()
    {
        summary.parent_request_key = Some(format!("a2a:task:{task_id}"));
    }

    summary
}

pub(super) struct ParsedSseEvent {
    pub(super) event: Option<String>,
    pub(super) id: Option<String>,
    pub(super) data: String,
    pub(super) data_bytes: usize,
    pub(super) truncated: bool,
}

#[derive(Default)]
struct SseStreamParser {
    pending_line: Vec<u8>,
    next_search_offset: usize,
    event_name: Option<String>,
    event_id: Option<String>,
    data: String,
    saw_data_field: bool,
    data_bytes: usize,
    data_truncated: bool,
    captured_data_bytes: usize,
}

impl SseStreamParser {
    fn push_bytes(&mut self, chunk: &[u8], is_final: bool) -> Vec<ParsedSseEvent> {
        let mut pending_line = std::mem::take(&mut self.pending_line);
        pending_line.extend_from_slice(chunk);
        let mut events = Vec::new();
        let mut line_start = 0usize;
        let mut search_offset = self.next_search_offset.min(pending_line.len());

        while let Some(relative_index) = pending_line[search_offset..]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            let index = search_offset + relative_index;
            let line = pending_line[line_start..index]
                .strip_suffix(b"\r")
                .unwrap_or(&pending_line[line_start..index]);
            self.process_line_bytes(line, &mut events);
            line_start = index + 1;
            search_offset = line_start;
        }

        if line_start > 0 {
            pending_line.drain(..line_start);
            self.next_search_offset = 0;
        } else {
            self.next_search_offset = pending_line.len();
        }

        if is_final {
            if !pending_line.is_empty() {
                let line = pending_line
                    .strip_suffix(b"\r")
                    .unwrap_or(pending_line.as_slice());
                self.process_line_bytes(line, &mut events);
                pending_line.clear();
            }
            self.next_search_offset = 0;
            self.flush_event(&mut events);
        }

        self.pending_line = pending_line;
        events
    }

    fn process_line_bytes(&mut self, line: &[u8], events: &mut Vec<ParsedSseEvent>) {
        let line = String::from_utf8_lossy(line);
        self.process_line(line.as_ref(), events);
    }

    fn process_line(&mut self, line: &str, events: &mut Vec<ParsedSseEvent>) {
        if line.is_empty() {
            self.flush_event(events);
            return;
        }
        if line.starts_with(':') {
            return;
        }
        let (field, value) = match line.split_once(':') {
            Some((field, rest)) => (field, rest.strip_prefix(' ').unwrap_or(rest)),
            None => (line, ""),
        };
        match field {
            "event" => self.event_name = Some(value.to_string()),
            "id" => self.event_id = Some(value.to_string()),
            "data" => self.push_data_line(value),
            _ => {}
        }
    }

    fn push_data_line(&mut self, value: &str) {
        let separator_len = usize::from(self.saw_data_field);
        self.saw_data_field = true;
        self.data_bytes = self
            .data_bytes
            .saturating_add(separator_len.saturating_add(value.len()));
        if self.data_truncated {
            return;
        }

        if separator_len == 1 {
            if self.captured_data_bytes == DEFAULT_HTTP_SSE_EVENT_CAPTURE_LIMIT_BYTES {
                self.data_truncated = true;
                return;
            }
            self.data.push('\n');
            self.captured_data_bytes += 1;
        }

        let remaining =
            DEFAULT_HTTP_SSE_EVENT_CAPTURE_LIMIT_BYTES.saturating_sub(self.captured_data_bytes);
        if remaining == 0 {
            if !value.is_empty() {
                self.data_truncated = true;
            }
            return;
        }

        let captured = truncate_to_utf8_boundary(value, remaining);
        self.data.push_str(captured);
        self.captured_data_bytes += captured.len();
        if captured.len() != value.len() {
            self.data_truncated = true;
        }
    }

    fn flush_event(&mut self, events: &mut Vec<ParsedSseEvent>) {
        if self.saw_data_field || self.event_name.is_some() || self.event_id.is_some() {
            events.push(ParsedSseEvent {
                event: self.event_name.take(),
                id: self.event_id.take(),
                data: std::mem::take(&mut self.data),
                data_bytes: std::mem::take(&mut self.data_bytes),
                truncated: std::mem::take(&mut self.data_truncated),
            });
            self.saw_data_field = false;
            self.captured_data_bytes = 0;
        }
    }
}

fn truncate_to_utf8_boundary(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = 0usize;
    for (index, _) in value.char_indices() {
        if index > max_bytes {
            break;
        }
        end = index;
    }
    if end == 0 && max_bytes == value.len() {
        value
    } else {
        &value[..end]
    }
}

#[cfg(test)]
pub(super) fn parse_sse_events(body_text: &str) -> Vec<ParsedSseEvent> {
    let mut parser = SseStreamParser::default();
    parser.push_bytes(body_text.as_bytes(), true)
}

#[cfg(test)]
pub(super) fn parse_sse_events_in_chunks(chunks: &[&str]) -> Vec<ParsedSseEvent> {
    let mut parser = SseStreamParser::default();
    let mut events = Vec::new();
    for chunk in chunks {
        events.extend(parser.push_bytes(chunk.as_bytes(), false));
    }
    events.extend(parser.push_bytes(&[], true));
    events
}

#[derive(Clone, Copy, Debug)]
pub(super) enum BodyCaptureDisposition {
    Capture,
    Omit,
}

pub(super) fn body_capture_disposition(content_type: Option<&str>) -> BodyCaptureDisposition {
    let Some(content_type) = content_type else {
        return BodyCaptureDisposition::Capture;
    };
    let content_type = content_type.trim().to_ascii_lowercase();
    if content_type.starts_with("image/")
        || content_type.starts_with("audio/")
        || content_type.starts_with("video/")
        || content_type.starts_with("application/octet-stream")
    {
        BodyCaptureDisposition::Omit
    } else {
        BodyCaptureDisposition::Capture
    }
}

fn is_sse_content_type(content_type: Option<&str>) -> bool {
    content_type
        .map(|value| value.trim().to_ascii_lowercase())
        .is_some_and(|value| value.starts_with("text/event-stream"))
}

pub(super) struct CapturedBodyMetadata<'a> {
    pub(super) total_bytes: usize,
    pub(super) truncated: bool,
    pub(super) omitted: bool,
    pub(super) content_type: Option<&'a str>,
    pub(super) content_encoding: Option<&'a str>,
}

fn emit_sse_event(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    sse_event: ParsedSseEvent,
) {
    let summary = if sse_event.truncated {
        ProtocolSummary::default()
    } else {
        extract_protocol_summary(telemetry, &sse_event.data)
    };
    let message = format!(
        "{} [stream event]",
        exchange_message(telemetry, HttpLifecyclePart::Response, &summary)
    );
    let mut extra_attributes = Vec::with_capacity(5);
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_sse_event",
        sse_event.event.as_deref().unwrap_or(""),
    );
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_sse_id",
        sse_event.id.as_deref().unwrap_or(""),
    );
    if sse_event.data_bytes > 0 {
        push_log_attr(
            &mut extra_attributes,
            "amber_sse_data_size_bytes",
            i64::try_from(sse_event.data_bytes).unwrap_or(i64::MAX),
        );
    }
    push_true_log_attr(
        &mut extra_attributes,
        "amber_sse_data_truncated",
        sse_event.truncated,
    );
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_sse_data",
        sse_event.data.as_str(),
    );
    emit_binding_log(
        span,
        telemetry,
        &summary,
        BindingLogSpec {
            level: Severity::Info,
            part: HttpLifecyclePart::Response,
            step: "stream_event",
            transport: "sse",
            event_name: "amber.binding.sse",
            message,
            extra_attributes,
        },
    );
}

pub(super) fn emit_body_event(
    span: &tracing::Span,
    telemetry: &HttpExchangeTelemetryContext,
    part: HttpLifecyclePart,
    event_name: &'static str,
    captured: &[u8],
    metadata: CapturedBodyMetadata<'_>,
) {
    let body_utf8 = !metadata.omitted && std::str::from_utf8(captured).is_ok();
    let body_text = if metadata.omitted || !body_utf8 {
        ""
    } else {
        std::str::from_utf8(captured).unwrap_or("")
    };
    let summary = if body_utf8 {
        extract_protocol_summary(telemetry, body_text)
    } else {
        ProtocolSummary::default()
    };
    let message = format!("{} [body]", exchange_message(telemetry, part, &summary));
    let mut extra_attributes = Vec::with_capacity(7);
    if metadata.total_bytes > 0 {
        push_log_attr(
            &mut extra_attributes,
            "amber_body_size_bytes",
            i64::try_from(metadata.total_bytes).unwrap_or(i64::MAX),
        );
    }
    push_true_log_attr(
        &mut extra_attributes,
        "amber_body_truncated",
        metadata.truncated,
    );
    push_true_log_attr(
        &mut extra_attributes,
        "amber_body_omitted",
        metadata.omitted,
    );
    if !body_utf8 {
        push_log_attr(&mut extra_attributes, "amber_body_utf8", false);
    }
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_body_content_type",
        metadata.content_type.unwrap_or(""),
    );
    push_nonempty_log_attr(
        &mut extra_attributes,
        "amber_body_content_encoding",
        metadata.content_encoding.unwrap_or(""),
    );
    push_nonempty_log_attr(&mut extra_attributes, "amber_body_text", body_text);
    emit_binding_log(
        span,
        telemetry,
        &summary,
        BindingLogSpec {
            level: Severity::Info,
            part,
            step: "body",
            transport: "http",
            event_name,
            message,
            extra_attributes,
        },
    );
}

struct CapturedBodyCompletion {
    span: tracing::Span,
    telemetry: HttpExchangeTelemetryContext,
    part: HttpLifecyclePart,
    event_name: &'static str,
    disposition: BodyCaptureDisposition,
    content_type: Option<String>,
    content_encoding: Option<String>,
}

fn emit_captured_body_completion(
    completion: &CapturedBodyCompletion,
    captured: &[u8],
    total_bytes: usize,
    truncated: bool,
    sse_parser: &mut Option<SseStreamParser>,
) {
    if let Some(mut parser) = sse_parser.take() {
        for sse_event in parser.push_bytes(&[], true) {
            emit_sse_event(&completion.span, &completion.telemetry, sse_event);
        }
    }
    let omitted = matches!(completion.disposition, BodyCaptureDisposition::Omit);
    emit_body_event(
        &completion.span,
        &completion.telemetry,
        completion.part,
        completion.event_name,
        captured,
        CapturedBodyMetadata {
            total_bytes,
            truncated,
            omitted,
            content_type: completion.content_type.as_deref(),
            content_encoding: completion.content_encoding.as_deref(),
        },
    );
}

pub(super) fn capture_box_body(
    body: BoxBody,
    span: tracing::Span,
    telemetry: HttpExchangeTelemetryContext,
    part: HttpLifecyclePart,
    event_name: &'static str,
    content_type: Option<String>,
    content_encoding: Option<String>,
) -> BoxBody {
    let disposition = body_capture_disposition(content_type.as_deref());
    let sse_enabled = matches!(disposition, BodyCaptureDisposition::Capture)
        && is_sse_content_type(content_type.as_deref());
    let expected_bytes = body
        .size_hint()
        .exact()
        .and_then(|bytes| usize::try_from(bytes).ok());
    let source = BodyStream::new(body);
    let captured = Vec::new();
    let total_bytes: usize = 0;
    let truncated = false;
    let sse_parser = sse_enabled.then(SseStreamParser::default);
    let body_event_emitted = false;
    let completion = CapturedBodyCompletion {
        span: span.clone(),
        telemetry: telemetry.clone(),
        part,
        event_name,
        disposition,
        content_type: content_type.clone(),
        content_encoding: content_encoding.clone(),
    };

    let stream = futures::stream::try_unfold(
        (
            source,
            span,
            telemetry,
            disposition,
            content_type,
            content_encoding,
            captured,
            total_bytes,
            truncated,
            sse_parser,
            body_event_emitted,
            expected_bytes,
            completion,
        ),
        move |(
            mut source,
            span,
            telemetry,
            disposition,
            content_type,
            content_encoding,
            mut captured,
            mut total_bytes,
            mut truncated,
            mut sse_parser,
            mut body_event_emitted,
            expected_bytes,
            completion,
        )| async move {
            match source.next().await {
                Some(Ok(frame)) => {
                    let frame_was_final = source.is_end_stream();
                    match frame.into_data() {
                        Ok(chunk) => {
                            total_bytes = total_bytes.saturating_add(chunk.len());
                            if matches!(disposition, BodyCaptureDisposition::Capture) && !truncated
                            {
                                let remaining = DEFAULT_HTTP_BODY_CAPTURE_LIMIT_BYTES
                                    .saturating_sub(captured.len());
                                if remaining == 0 {
                                    truncated = true;
                                } else if chunk.len() <= remaining {
                                    captured.extend_from_slice(&chunk);
                                } else {
                                    captured.extend_from_slice(&chunk[..remaining]);
                                    truncated = true;
                                }
                            }
                            if let Some(parser) = sse_parser.as_mut() {
                                for sse_event in parser.push_bytes(chunk.as_ref(), false) {
                                    emit_sse_event(&span, &telemetry, sse_event);
                                }
                            }
                            let body_complete = frame_was_final
                                || expected_bytes.is_some_and(|bytes| total_bytes >= bytes);
                            if body_complete && !body_event_emitted {
                                emit_captured_body_completion(
                                    &completion,
                                    &captured,
                                    total_bytes,
                                    truncated,
                                    &mut sse_parser,
                                );
                                body_event_emitted = true;
                            }

                            let next_state = (
                                source,
                                span,
                                telemetry,
                                disposition,
                                content_type,
                                content_encoding,
                                captured,
                                total_bytes,
                                truncated,
                                sse_parser,
                                body_event_emitted,
                                expected_bytes,
                                completion,
                            );
                            Ok(Some((Frame::data(chunk), next_state)))
                        }
                        Err(frame) => {
                            let body_complete = frame_was_final
                                || expected_bytes.is_some_and(|bytes| total_bytes >= bytes);
                            if body_complete && !body_event_emitted {
                                emit_captured_body_completion(
                                    &completion,
                                    &captured,
                                    total_bytes,
                                    truncated,
                                    &mut sse_parser,
                                );
                                body_event_emitted = true;
                            }
                            let next_state = (
                                source,
                                span,
                                telemetry,
                                disposition,
                                content_type,
                                content_encoding,
                                captured,
                                total_bytes,
                                truncated,
                                sse_parser,
                                body_event_emitted,
                                expected_bytes,
                                completion,
                            );
                            Ok(Some((frame, next_state)))
                        }
                    }
                }
                Some(Err(err)) => {
                    let message = match part {
                        HttpLifecyclePart::Request => {
                            format!("{} request body stream error", telemetry.local_role())
                        }
                        HttpLifecyclePart::Response => {
                            format!("{} response body stream error", telemetry.local_role())
                        }
                    };
                    let summary = telemetry.summary_snapshot();
                    let mut extra_attributes = Vec::with_capacity(1);
                    push_log_attr(&mut extra_attributes, "amber_body_error", err.to_string());
                    emit_binding_log(
                        &span,
                        &telemetry,
                        &summary,
                        BindingLogSpec {
                            level: Severity::Warn,
                            part,
                            step: "body",
                            transport: if sse_enabled { "sse" } else { "http" },
                            event_name,
                            message,
                            extra_attributes,
                        },
                    );
                    Err(err)
                }
                None => {
                    if !body_event_emitted {
                        emit_captured_body_completion(
                            &completion,
                            &captured,
                            total_bytes,
                            truncated,
                            &mut sse_parser,
                        );
                    }
                    Ok(None)
                }
            }
        },
    );

    http_body_util::BodyExt::map_err(StreamBody::new(stream), |err| err).boxed()
}
