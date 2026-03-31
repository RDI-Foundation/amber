use super::*;

pub(super) fn otelcol_config_content() -> String {
    format!(
        r#"
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:{OTELCOL_SERVICE_PORT_GRPC}
      http:
        endpoint: 0.0.0.0:{OTELCOL_SERVICE_PORT_HTTP}
  filelog/kubernetes:
    include:
      - /var/log/containers/*_${{env:{SCENARIO_RUN_ID_ENV}}}_main-*.log
    start_at: end
    include_file_path: true
    operators:
      - type: container
      - type: json_parser
        if: body matches "^[{{]"
        parse_from: body
      - type: severity_parser
        if: attributes.level != nil
        parse_from: attributes.level
      - type: move
        if: attributes.message != nil
        from: attributes.message
        to: body

processors:
  memory_limiter:
    check_interval: 1s
    limit_mib: 256
    spike_limit_mib: 128
  batch: {{}}
  k8sattributes/program_logs:
    auth_type: serviceAccount
    extract:
      metadata:
        - k8s.namespace.name
        - k8s.pod.name
        - k8s.pod.uid
        - k8s.container.name
      annotations:
        - tag_name: service.name
          key: resource.opentelemetry.io/service.name
          from: pod
        - tag_name: amber.component.moniker
          key: amber.io/component-moniker
          from: pod
    pod_association:
      - sources:
          - from: resource_attribute
            name: k8s.pod.uid
  transform/program_logs:
    error_mode: ignore
    log_statements:
      - context: scope
        statements:
          - set(scope.name, "amber.program")
      - context: log
        statements:
          - set(log.attributes["amber_stream"], log.attributes["log.iostream"]) where log.attributes["amber_stream"] == nil and log.attributes["log.iostream"] != nil
          - set(log.severity_number, SEVERITY_NUMBER_ERROR) where log.severity_number == 0 and IsString(log.body) and IsMatch(log.body, "(?i)\b(error|failed|exception|fatal|panic)\b")
          - set(log.severity_number, SEVERITY_NUMBER_WARN) where log.severity_number == 0 and IsString(log.body) and IsMatch(log.body, "(?i)\b(warn|warning)\b")
          - set(log.severity_number, SEVERITY_NUMBER_WARN) where log.severity_number == 0 and log.attributes["amber_stream"] == "stderr"
          - set(log.severity_number, SEVERITY_NUMBER_INFO) where log.severity_number == 0
          - set(log.severity_text, "Error") where log.severity_text == "" and log.severity_number >= SEVERITY_NUMBER_ERROR
          - set(log.severity_text, "Warning") where log.severity_text == "" and log.severity_number >= SEVERITY_NUMBER_WARN and log.severity_number < SEVERITY_NUMBER_ERROR
          - set(log.severity_text, "Information") where log.severity_text == "" and log.severity_number >= SEVERITY_NUMBER_INFO and log.severity_number < SEVERITY_NUMBER_WARN
  resource/amber:
    attributes:
      - key: amber.scenario.run_id
        action: upsert
        value: ${{env:{SCENARIO_RUN_ID_ENV}}}

exporters:
  otlphttp/upstream:
    endpoint: ${{env:{OTELCOL_UPSTREAM_ENV}}}
    compression: none
    encoding: proto

service:
  telemetry:
    logs:
      level: warn
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, resource/amber, batch]
      exporters: [otlphttp/upstream]
    logs/otlp:
      receivers: [otlp]
      processors: [memory_limiter, resource/amber, batch]
      exporters: [otlphttp/upstream]
    logs/program:
      receivers: [filelog/kubernetes]
      processors: [memory_limiter, k8sattributes/program_logs, transform/program_logs, resource/amber, batch]
      exporters: [otlphttp/upstream]
    metrics:
      receivers: [otlp]
      processors: [memory_limiter, resource/amber, batch]
      exporters: [otlphttp/upstream]
"#
    )
}

pub(super) fn component_pod_annotations(component_moniker: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "resource.opentelemetry.io/service.name".to_string(),
            kubernetes_component_service_name(component_moniker),
        ),
        (
            "amber.io/component-moniker".to_string(),
            component_moniker.to_string(),
        ),
    ])
}

pub(super) fn kubernetes_component_service_name(component_moniker: &str) -> String {
    format!("amber.{}", sanitize_component_moniker(component_moniker))
}

pub(super) fn sanitize_component_moniker(component_moniker: &str) -> String {
    let sanitized = component_moniker.trim_matches('/').replace('/', ".");
    if sanitized.is_empty() {
        "root".to_string()
    } else {
        sanitized
    }
}

pub(super) fn push_program_observability_env(
    env: &mut Vec<EnvVar>,
    component_moniker: &str,
    scenario_scope: Option<&str>,
) {
    env.push(EnvVar::from_field_ref(
        SCENARIO_RUN_ID_ENV,
        "metadata.namespace",
    ));
    env.push(EnvVar::literal("OTEL_TRACES_SAMPLER", "always_on"));
    env.push(EnvVar::literal(
        "OTEL_EXPORTER_OTLP_PROTOCOL",
        "http/protobuf",
    ));
    env.push(EnvVar::literal(
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        ROUTER_OTLP_ENDPOINT,
    ));
    env.push(EnvVar::literal(
        "AMBER_COMPONENT_MONIKER",
        component_moniker,
    ));
    if let Some(scope) = scenario_scope {
        env.push(EnvVar::literal("AMBER_SCENARIO_SCOPE", scope));
    }
}

pub(super) fn render_kubernetes_image(
    image: &ProgramImagePlan,
    root_leaf_by_path: &BTreeMap<&str, &rc::SchemaLeaf>,
    service_name: &str,
    component: &str,
    image_source: Option<&ProgramImageSource>,
) -> KubernetesResult<(String, Option<String>)> {
    match image {
        ProgramImagePlan::Static(value) => Ok((value.clone(), None)),
        ProgramImagePlan::RuntimeTemplate(parts) => {
            let [ProgramImagePart::RootConfigPath(path)] = parts.as_slice() else {
                return Err(program_image_error(
                    component,
                    "resolves to a mixed runtime image template, but kubernetes output only \
                     supports runtime images that resolve to exactly one concrete config value \
                     (for example `${config.image}`).",
                    image_source,
                ));
            };

            let leaf = root_leaf_by_path.get(path.as_str()).ok_or_else(|| {
                program_image_error(
                    component,
                    format!(
                        "references runtime config.{path}, but that path does not resolve to a \
                         concrete config value"
                    ),
                    image_source,
                )
            })?;
            if leaf.secret {
                return Err(program_image_error(
                    component,
                    format!(
                        "references config.{path}, but kubernetes runtime image interpolation \
                         does not support secret config values"
                    ),
                    image_source,
                ));
            }

            let env_var = rc::env_var_for_path(path).map_err(|e| {
                ReporterError::new(format!(
                    "failed to map runtime image path config.{path} to env var: {e}"
                ))
            })?;
            Ok((format!("amber-runtime-image-{service_name}"), Some(env_var)))
        }
    }
}

pub(super) fn render_root_config_env_content(
    leaves: &[(&String, &RootInputDescriptor)],
    heading: &str,
) -> KubernetesResult<String> {
    let mut env_content = String::new();
    env_content.push_str(heading);
    env_content.push('\n');

    for (path, input) in leaves {
        let value = input
            .default_env_value(path)
            .map_err(|err| ReporterError::new(err.to_string()))?
            .unwrap_or_default();
        env_content.push_str(&format!("{}={value}\n", input.env_var));
    }

    Ok(env_content)
}

pub(super) fn program_image_source(
    compiled: &CompiledScenario,
    scenario: &Scenario,
    component: ComponentId,
    origin: &ProgramImageOrigin,
) -> Option<ProgramImageSource> {
    match origin {
        ProgramImageOrigin::ProgramImage => component_program_image_source(compiled, component),
        ProgramImageOrigin::ComponentConfigPath(path) => {
            component_config_image_source(compiled, scenario, component, path)
        }
    }
}

pub(super) fn component_config_image_source(
    compiled: &CompiledScenario,
    scenario: &Scenario,
    component: ComponentId,
    path: &str,
) -> Option<ProgramImageSource> {
    let component = scenario.component(component);
    let parent = component.parent?;
    let child_name = component.moniker.local_name()?;

    let (store, provenance) = compiled.source_context()?;
    let provenance = provenance.for_component(parent);
    let url = &provenance.resolved_url;
    let stored = store.get_source(url)?;
    let root_span: SourceSpan = (0usize, stored.source.len()).into();
    let mut config_ptr = PointerBuf::from_tokens(["components", child_name, "config"]);
    for segment in path.split('.').filter(|segment| !segment.is_empty()) {
        config_ptr.push_back(segment);
    }
    let span = span_for_json_pointer(stored.source.as_ref(), root_span, &config_ptr.to_string())?;
    let src = NamedSource::new(crate::frontend::store::display_url(url), stored.source)
        .with_language("json5");
    Some(ProgramImageSource {
        src,
        span,
        label: "component config image interpolation here".to_string(),
    })
}

pub(super) fn component_program_image_source(
    compiled: &CompiledScenario,
    component: ComponentId,
) -> Option<ProgramImageSource> {
    let (store, provenance) = compiled.source_context()?;
    let provenance = provenance.for_component(component);
    let url = &provenance.resolved_url;
    let stored = store.get_source(url)?;
    let program = stored.spans.program.as_ref()?;
    let root_span: SourceSpan = (0usize, stored.source.len()).into();
    let span = span_for_json_pointer(stored.source.as_ref(), root_span, "/program/image")
        .unwrap_or(program.whole);
    let src = NamedSource::new(crate::frontend::store::display_url(url), stored.source)
        .with_language("json5");
    Some(ProgramImageSource {
        src,
        span,
        label: "program.image interpolation here".to_string(),
    })
}

pub(super) fn program_image_error(
    component: &str,
    message: impl Into<String>,
    image_source: Option<&ProgramImageSource>,
) -> ReporterError {
    let mut error = ReporterError::new(format!("program.image in {component} {}", message.into()));
    if let Some(image_source) = image_source {
        error = error
            .with_source_code(image_source.src.clone())
            .with_labels(vec![LabeledSpan::new_primary_with_span(
                Some(image_source.label.clone()),
                image_source.span,
            )]);
    }
    error
}

pub(super) fn mesh_secret_name(service: &str) -> String {
    format!("{service}-mesh")
}

pub(super) fn default_container_security_context() -> SecurityContext {
    SecurityContext {
        allow_privilege_escalation: Some(false),
        capabilities: Some(Capabilities {
            drop: vec!["ALL".to_string()],
        }),
        read_only_root_filesystem: None,
        run_as_non_root: None,
        run_as_user: None,
        seccomp_profile: Some(SeccompProfile {
            profile_type: "RuntimeDefault".to_string(),
        }),
    }
}

pub(super) fn harden_container(mut container: Container) -> Container {
    container.security_context = Some(default_container_security_context());
    container
}

pub(super) fn harden_read_only_container(mut container: Container) -> Container {
    container = harden_container(container);
    if let Some(security_context) = &mut container.security_context {
        security_context.read_only_root_filesystem = Some(true);
    }
    container
}

pub(super) fn harden_non_root_internal_container(mut container: Container) -> Container {
    container = harden_read_only_container(container);
    if let Some(security_context) = &mut container.security_context {
        security_context.run_as_non_root = Some(true);
        security_context.run_as_user = Some(INTERNAL_RUNTIME_UID);
    }
    container
}

pub(super) fn build_mesh_config_wait_init_container(
    helper_image: &str,
    expected_scope: &str,
) -> Container {
    harden_non_root_internal_container(Container {
        name: "wait-mesh-config".to_string(),
        image: helper_image.to_string(),
        command: vec![
            "/amber-helper".to_string(),
            "wait-mesh-config".to_string(),
            format!("{MESH_CONFIG_DIR}/{MESH_CONFIG_FILENAME}"),
            expected_scope.to_string(),
            MESH_CONFIG_WAIT_TIMEOUT_SECS.to_string(),
        ],
        args: Vec::new(),
        env: Vec::new(),
        env_from: Vec::new(),
        ports: Vec::new(),
        readiness_probe: None,
        security_context: None,
        volume_mounts: vec![VolumeMount {
            name: MESH_SECRET_VOLUME_NAME.to_string(),
            mount_path: MESH_CONFIG_DIR.to_string(),
            read_only: Some(true),
        }],
    })
}

pub(super) fn encode_scenario_digest(digest: &[u8; 32]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(digest);
    format!("sha256:{encoded}")
}

pub(super) fn provisioner_job_name(digest: &[u8; 32]) -> String {
    let digest_hex: String = digest[..4].iter().map(|b| format!("{:02x}", b)).collect();
    truncate_dns_name(&format!("{PROVISIONER_NAME}-{digest_hex}"), 63)
}

pub(super) fn generate_namespace_name(s: &Scenario, scenario_digest: &[u8; 32]) -> String {
    let root = s.component(s.root);
    let short_name = root
        .moniker
        .local_name()
        .unwrap_or("scenario")
        .to_lowercase();
    // Get digest bytes and encode as hex (DNS-safe)
    let digest_hex: String = scenario_digest[..4]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();

    let base = format!("{}-{}", sanitize_dns_name(&short_name), digest_hex);
    truncate_dns_name(&base, 63)
}

pub(super) fn service_name(id: ComponentId, local_name: &str) -> String {
    let slug = sanitize_dns_name(local_name);
    let name = format!("c{}-{}", id.0, slug);
    truncate_dns_name(&name, 63)
}

pub(super) fn sanitize_dns_name(s: &str) -> String {
    let mut out = String::new();
    for ch in s.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else {
            out.push('-');
        }
    }
    // Remove leading/trailing hyphens and collapse multiple hyphens.
    let out = out.trim_matches('-');
    let mut result = String::new();
    let mut last_hyphen = false;
    for ch in out.chars() {
        if ch == '-' {
            if !last_hyphen {
                result.push(ch);
                last_hyphen = true;
            }
        } else {
            result.push(ch);
            last_hyphen = false;
        }
    }
    if result.is_empty() {
        "component".to_string()
    } else {
        result
    }
}

pub(super) fn truncate_dns_name(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        s[..max_len].trim_end_matches('-').to_string()
    }
}

pub(super) fn sanitize_label_value(s: &str) -> String {
    // Kubernetes label values: max 63 chars, alphanumeric, -, _, .
    let mut out = String::new();
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            out.push(ch);
        }
    }
    truncate_dns_name(&out, 63)
}

pub(super) fn storage_request_for(
    scenario: &Scenario,
    identity: &crate::targets::storage::StorageIdentity,
) -> String {
    scenario
        .component(identity.owner)
        .resources
        .get(identity.resource.as_str())
        .and_then(|resource| resource.params.size.as_deref())
        .unwrap_or(DEFAULT_STORAGE_REQUEST)
        .to_string()
}

pub(super) fn storage_claim_name(identity: &crate::targets::storage::StorageIdentity) -> String {
    let prefix = format!(
        "storage-{}-{}",
        sanitize_dns_name(identity.owner_moniker.as_str()),
        sanitize_dns_name(identity.resource.as_str())
    );
    truncate_dns_name_with_hash(&prefix, &identity.hash_suffix(), 63)
}

pub(super) fn truncate_dns_name_with_hash(prefix: &str, hash: &str, max_len: usize) -> String {
    let max_prefix_len = max_len.saturating_sub(hash.len() + 1);
    let prefix = truncate_dns_name(prefix, max_prefix_len);
    format!("{prefix}-{hash}")
}

pub(super) fn sanitize_port_name(s: &str) -> String {
    // Port names: max 15 chars, lowercase alphanumeric and hyphens.
    let sanitized = sanitize_dns_name(s);
    truncate_dns_name(&sanitized, 15)
}

pub(super) fn build_component_config_env(
    root_inputs: &BTreeMap<String, RootInputDescriptor>,
    allowed_leaf_paths: &std::collections::BTreeSet<String>,
) -> Result<Vec<EnvVar>, ReporterError> {
    let mut env = Vec::new();

    for (path, input) in root_inputs {
        if !allowed_leaf_paths.contains(path) {
            continue;
        }

        if input.secret {
            env.push(EnvVar::from_secret(
                &input.env_var,
                ROOT_CONFIG_SECRET_NAME,
                &input.env_var,
            ));
        } else {
            env.push(EnvVar::from_config_map(
                &input.env_var,
                ROOT_CONFIG_CONFIGMAP_NAME,
                &input.env_var,
            ));
        }
    }

    Ok(env)
}

pub(super) fn build_helper_runner_container(
    program_image: String,
    ports: Vec<ContainerPort>,
    env: Vec<EnvVar>,
) -> (Container, Vec<Volume>) {
    let container = harden_container(Container {
        name: "main".to_string(),
        image: program_image,
        command: vec![HELPER_BIN_PATH.to_string(), "run".to_string()],
        args: Vec::new(),
        env,
        env_from: Vec::new(),
        ports,
        readiness_probe: None,
        security_context: None,
        volume_mounts: vec![VolumeMount {
            name: HELPER_VOLUME_NAME.to_string(),
            mount_path: HELPER_BIN_DIR.to_string(),
            read_only: Some(true),
        }],
    });
    let volumes = vec![Volume::empty_dir(HELPER_VOLUME_NAME)];
    (container, volumes)
}

// ---- Runtime config / helper mode support ----

pub(super) fn to_yaml<T: Serialize>(value: &T) -> Result<String, ReporterError> {
    serde_yaml::to_string(value)
        .map_err(|e| ReporterError::new(format!("failed to serialize YAML: {e}")))
}
