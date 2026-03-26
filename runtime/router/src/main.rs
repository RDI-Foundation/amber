use amber_mesh::telemetry::{
    OtlpIdentity, OtlpInstallMode, SubscriberFormat, SubscriberOptions, init_otel_tracer,
    init_subscriber, observability_log_scope_name, shutdown_tracer_provider,
    structured_logs_enabled, suppress_otlp_bridge_target,
};
use amber_router::{config_from_env, prebound_listeners_from_env, run_with_listeners};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let config = match config_from_env() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("router config error: {err}");
            std::process::exit(1);
        }
    };
    let listeners = match prebound_listeners_from_env() {
        Ok(listeners) => listeners,
        Err(err) => {
            eprintln!("router listener setup error: {err}");
            std::process::exit(1);
        }
    };

    init_tracing(&config);

    if let Err(err) = run_with_listeners(config, listeners).await {
        tracing::error!("router failed: {err}");
        shutdown_tracer_provider();
        std::process::exit(1);
    }

    shutdown_tracer_provider();
}

fn init_tracing(config: &amber_mesh::MeshConfig) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("warn,amber_router=info,amber.binding=info"));
    let tracer = match init_otel_tracer(
        OtlpIdentity {
            moniker: config.identity.id.as_str(),
            component_kind: Some("router"),
            scenario_scope: config.identity.mesh_scope.as_deref(),
        },
        OtlpInstallMode::BatchTokio,
    ) {
        Ok(tracer) => tracer,
        Err(err) => {
            eprintln!("warning: failed to initialize OTLP tracing: {err}");
            None
        }
    };
    let format = if structured_logs_enabled() {
        SubscriberFormat::RuntimeJson
    } else {
        SubscriberFormat::RuntimeText
    };
    let telemetry_filter = suppress_otlp_bridge_target(
        suppress_otlp_bridge_target(filter.clone(), "amber.binding"),
        "amber.internal",
    );
    init_subscriber(
        filter,
        tracer,
        format,
        SubscriberOptions {
            telemetry_filter: Some(telemetry_filter),
            log_scope_name: Some(observability_log_scope_name(Some("router"))),
            ..SubscriberOptions::default()
        },
    );
}
