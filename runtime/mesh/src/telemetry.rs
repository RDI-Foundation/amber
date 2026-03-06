use std::{borrow::Cow, sync::OnceLock, time::SystemTime};

use opentelemetry::{
    InstrumentationScope, Key, KeyValue, global,
    logs::{AnyValue, LogRecord as _, Logger as _, LoggerProvider as _, Severity},
    trace::{SpanId, TraceFlags, TraceId, TracerProvider as _},
};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, SpanExporter, WithExportConfig as _};
use opentelemetry_sdk::{
    Resource, logs as sdklogs, propagation::TraceContextPropagator, trace as sdktrace,
};
use tracing_error::ErrorLayer;
use tracing_subscriber::{EnvFilter, Layer as _, Registry, fmt as tracing_fmt, prelude::*};

pub const COMPONENT_MONIKER_ENV: &str = "AMBER_COMPONENT_MONIKER";
pub const SCENARIO_RUN_ID_ENV: &str = "AMBER_SCENARIO_RUN_ID";
pub const SCENARIO_SCOPE_ENV: &str = "AMBER_SCENARIO_SCOPE";
pub const LOG_FORMAT_ENV: &str = "AMBER_LOG_FORMAT";
pub const OTLP_ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

const OTEL_SCOPE_NAME: &str = "amber";

static LOGGER_PROVIDER: OnceLock<sdklogs::SdkLoggerProvider> = OnceLock::new();
static TRACER_PROVIDER: OnceLock<sdktrace::SdkTracerProvider> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub enum OtlpInstallMode {
    BatchTokio,
    Simple,
}

#[derive(Clone, Copy, Debug)]
pub struct OtlpIdentity<'a> {
    pub moniker: &'a str,
    pub component_kind: Option<&'a str>,
    pub scenario_scope: Option<&'a str>,
}

#[derive(Clone, Copy, Debug)]
pub enum SubscriberFormat {
    CliText,
    RuntimeText,
    RuntimeJson,
}

#[derive(Debug, Default)]
pub struct SubscriberOptions {
    pub include_error_layer: bool,
    pub telemetry_filter: Option<EnvFilter>,
    pub log_scope_name: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub struct OtlpTraceContext {
    pub trace_id: TraceId,
    pub span_id: SpanId,
    pub trace_flags: Option<TraceFlags>,
}

#[derive(Debug)]
pub struct OtlpLogMessage {
    pub scope_name: &'static str,
    pub target: &'static str,
    pub event_name: &'static str,
    pub severity: Severity,
    pub body: String,
    pub attributes: Vec<(Key, AnyValue)>,
    pub trace_context: Option<OtlpTraceContext>,
}

pub fn init_subscriber(
    filter: EnvFilter,
    tracer: Option<sdktrace::Tracer>,
    format: SubscriberFormat,
    options: SubscriberOptions,
) {
    type BoxLayer = Box<dyn tracing_subscriber::Layer<Registry> + Send + Sync + 'static>;

    let mut layers: Vec<BoxLayer> = Vec::new();
    layers.push(match format {
        SubscriberFormat::CliText => Box::new(tracing_fmt::layer().with_filter(filter.clone())),
        SubscriberFormat::RuntimeText => Box::new(
            tracing_fmt::layer()
                .with_ansi(false)
                .with_target(false)
                .without_time()
                .with_filter(filter.clone()),
        ),
        SubscriberFormat::RuntimeJson => Box::new(
            tracing_fmt::layer()
                .json()
                .flatten_event(true)
                .with_current_span(true)
                .with_span_list(false)
                .with_ansi(false)
                .without_time()
                .with_target(false)
                .with_filter(filter.clone()),
        ),
    });

    if options.include_error_layer {
        layers.push(Box::new(ErrorLayer::default().with_filter(filter.clone())));
    }

    let otel_filter = options
        .telemetry_filter
        .unwrap_or_else(|| default_telemetry_filter(filter.clone()));

    if let Some(tracer) = tracer {
        layers.push(Box::new(
            tracing_opentelemetry::layer()
                .with_context_activation(true)
                .with_tracer(tracer)
                .with_filter(otel_filter.clone()),
        ));
    }

    if let Some(provider) = LOGGER_PROVIDER.get() {
        let provider = FixedScopeLoggerProvider {
            inner: provider,
            scope_name: options.log_scope_name.unwrap_or("amber"),
        };
        layers.push(Box::new(
            OpenTelemetryTracingBridge::new(&provider).with_filter(otel_filter),
        ));
    }

    tracing_subscriber::registry().with(layers).init();
}

struct FixedScopeLoggerProvider<'a, P> {
    inner: &'a P,
    scope_name: &'static str,
}

impl<P> opentelemetry::logs::LoggerProvider for FixedScopeLoggerProvider<'_, P>
where
    P: opentelemetry::logs::LoggerProvider + Send + Sync,
{
    type Logger = P::Logger;

    fn logger_with_scope(&self, _scope: InstrumentationScope) -> Self::Logger {
        self.inner.logger(self.scope_name as &'static str)
    }

    fn logger(&self, _name: impl Into<Cow<'static, str>>) -> Self::Logger {
        self.inner.logger(self.scope_name as &'static str)
    }
}

pub fn structured_logs_enabled() -> bool {
    if let Ok(value) = std::env::var(LOG_FORMAT_ENV) {
        let value = value.trim();
        if value.eq_ignore_ascii_case("json") {
            return true;
        }
        if value.eq_ignore_ascii_case("text") {
            return false;
        }
    }

    false
}

pub fn init_otel_tracer(
    identity: OtlpIdentity<'_>,
    install_mode: OtlpInstallMode,
) -> Result<Option<sdktrace::Tracer>, String> {
    let Some(endpoint) = otlp_endpoint() else {
        return Ok(None);
    };

    if LOGGER_PROVIDER.get().is_some() || TRACER_PROVIDER.get().is_some() {
        return Err("OTLP telemetry already initialized".to_string());
    }

    global::set_text_map_propagator(TraceContextPropagator::new());

    let resource = build_resource(identity);
    let logger_provider = build_logger_provider(endpoint.as_str(), resource.clone(), install_mode)
        .map_err(|err| format!("failed to build OTLP log pipeline: {err}"))?;
    let tracer_provider = build_tracer_provider(endpoint.as_str(), resource, install_mode)
        .map_err(|err| format!("failed to build OTLP tracer pipeline: {err}"))?;
    let tracer = tracer_provider.tracer(OTEL_SCOPE_NAME);

    LOGGER_PROVIDER
        .set(logger_provider)
        .map_err(|_| "OTLP logger provider already initialized".to_string())?;
    TRACER_PROVIDER
        .set(tracer_provider.clone())
        .map_err(|_| "OTLP tracer provider already initialized".to_string())?;
    global::set_tracer_provider(tracer_provider);

    Ok(Some(tracer))
}

pub fn shutdown_tracer_provider() {
    if let Some(provider) = LOGGER_PROVIDER.get() {
        let _ = provider.shutdown();
    }
    if let Some(provider) = TRACER_PROVIDER.get() {
        let _ = provider.shutdown();
    }
}

pub fn emit_otlp_log(message: OtlpLogMessage) {
    let Some(provider) = LOGGER_PROVIDER.get() else {
        return;
    };

    let logger = provider.logger(message.scope_name);
    let mut record = logger.create_log_record();
    let now = SystemTime::now();
    record.set_timestamp(now);
    record.set_observed_timestamp(now);
    record.set_target(message.target);
    record.set_event_name(message.event_name);
    record.set_severity_number(message.severity);
    record.set_severity_text(message.severity.name());
    record.set_body(message.body.into());
    if !message.attributes.is_empty() {
        record.add_attributes(message.attributes);
    }
    if let Some(context) = message.trace_context {
        record.set_trace_context(context.trace_id, context.span_id, context.trace_flags);
    }
    logger.emit(record);
}

pub fn suppress_otlp_bridge_target(filter: EnvFilter, target: &'static str) -> EnvFilter {
    let directive = format!("{target}=off")
        .parse()
        .expect("valid OTLP bridge suppression filter");
    filter.add_directive(directive)
}

fn build_resource(identity: OtlpIdentity<'_>) -> Resource {
    let run_id = std::env::var(SCENARIO_RUN_ID_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let sanitized_moniker = sanitize_moniker(identity.moniker);
    let entity_kind = observability_entity_kind(identity.component_kind);
    let service_suffix = observability_service_suffix(identity.component_kind, &sanitized_moniker);
    let service_name = match run_id.as_deref() {
        Some(run_id) => format!("amber.{run_id}.{service_suffix}"),
        None => format!("amber.{service_suffix}"),
    };
    let mut resource_attributes = vec![
        KeyValue::new("service.name", service_name),
        KeyValue::new("amber.observability.entity_kind", entity_kind),
    ];
    if entity_kind == "component" {
        resource_attributes.push(KeyValue::new(
            "amber.component.moniker",
            identity.moniker.to_string(),
        ));
    }
    if let Some(component_kind) = identity.component_kind.filter(|kind| *kind != "router") {
        resource_attributes.push(KeyValue::new(
            "amber.component.kind",
            component_kind.to_string(),
        ));
    }
    if let Some(run_id) = run_id {
        resource_attributes.push(KeyValue::new("amber.scenario.run_id", run_id));
    }
    if let Some(scope) = identity
        .scenario_scope
        .and_then(|value| (!value.trim().is_empty()).then_some(value))
    {
        resource_attributes.push(KeyValue::new("amber.scenario.scope", scope.to_string()));
    }

    Resource::builder()
        .with_attributes(resource_attributes)
        .build()
}

fn observability_entity_kind(component_kind: Option<&str>) -> &'static str {
    match component_kind {
        Some("router") => "binding",
        _ => "component",
    }
}

fn observability_service_suffix(component_kind: Option<&str>, moniker: &str) -> String {
    match component_kind {
        Some("router") => "bindings".to_string(),
        _ => moniker.to_string(),
    }
}

fn build_tracer_provider(
    endpoint: &str,
    resource: Resource,
    install_mode: OtlpInstallMode,
) -> Result<sdktrace::SdkTracerProvider, String> {
    let exporter = SpanExporter::builder()
        .with_http()
        .with_endpoint(signal_endpoint(endpoint, "/v1/traces"))
        .build()
        .map_err(|err| err.to_string())?;
    let builder = sdktrace::SdkTracerProvider::builder().with_resource(resource);
    let builder = match install_mode {
        OtlpInstallMode::BatchTokio => builder.with_batch_exporter(exporter),
        OtlpInstallMode::Simple => builder.with_simple_exporter(exporter),
    };
    Ok(builder.build())
}

fn build_logger_provider(
    endpoint: &str,
    resource: Resource,
    install_mode: OtlpInstallMode,
) -> Result<sdklogs::SdkLoggerProvider, String> {
    let exporter = LogExporter::builder()
        .with_http()
        .with_endpoint(signal_endpoint(endpoint, "/v1/logs"))
        .build()
        .map_err(|err| err.to_string())?;
    let builder = sdklogs::SdkLoggerProvider::builder().with_resource(resource);
    let builder = match install_mode {
        OtlpInstallMode::BatchTokio => builder.with_batch_exporter(exporter),
        OtlpInstallMode::Simple => builder.with_simple_exporter(exporter),
    };
    Ok(builder.build())
}

fn otlp_endpoint() -> Option<String> {
    std::env::var(OTLP_ENDPOINT_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn signal_endpoint(endpoint: &str, signal_path: &str) -> String {
    if endpoint.ends_with(signal_path) {
        endpoint.to_string()
    } else {
        format!(
            "{}/{}",
            endpoint.trim_end_matches('/'),
            signal_path.trim_start_matches('/')
        )
    }
}

fn sanitize_moniker(moniker: &str) -> String {
    let sanitized = moniker.trim_matches('/').replace('/', ".");
    if sanitized.is_empty() {
        "root".to_string()
    } else {
        sanitized
    }
}

fn default_telemetry_filter(filter: EnvFilter) -> EnvFilter {
    filter
        .add_directive("h2=off".parse().expect("valid h2 filter"))
        .add_directive("hyper=off".parse().expect("valid hyper filter"))
        .add_directive(
            "opentelemetry=off"
                .parse()
                .expect("valid opentelemetry filter"),
        )
        .add_directive(
            "opentelemetry_sdk=off"
                .parse()
                .expect("valid opentelemetry_sdk filter"),
        )
        .add_directive("reqwest=off".parse().expect("valid reqwest filter"))
        .add_directive("tonic=off".parse().expect("valid tonic filter"))
        .add_directive(
            "tracing_opentelemetry=off"
                .parse()
                .expect("valid tracing_opentelemetry filter"),
        )
}

pub fn observability_log_scope_name(component_kind: Option<&str>) -> &'static str {
    match component_kind {
        Some("router") => "amber.binding",
        Some("program") => "amber.program",
        _ => "amber.proxy",
    }
}

#[cfg(test)]
mod tests {
    use super::observability_log_scope_name;

    #[test]
    fn log_scope_names_match_observability_entities() {
        assert_eq!(
            observability_log_scope_name(Some("router")),
            "amber.binding"
        );
        assert_eq!(
            observability_log_scope_name(Some("program")),
            "amber.program"
        );
        assert_eq!(observability_log_scope_name(None), "amber.proxy");
        assert_eq!(observability_log_scope_name(Some("cli")), "amber.proxy");
    }
}
