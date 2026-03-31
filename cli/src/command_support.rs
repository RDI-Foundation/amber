use super::*;

pub(crate) fn load_router_config_optional(args: &ProxyArgs) -> Result<Option<MeshConfig>> {
    if let Some(b64) = args.router_config_b64.as_ref() {
        return amber_mesh::decode_config_b64(b64)
            .map(Some)
            .map_err(|err| miette::miette!("invalid router config: {err}"));
    }

    if let Some(path) = args.router_config.as_ref() {
        let raw = fs::read_to_string(path).map_err(|err| {
            miette::miette!("failed to read router config {}: {err}", path.display())
        })?;
        let trimmed = raw.trim();
        if trimmed.starts_with('{') {
            let parsed = serde_json::from_str(trimmed)
                .map_err(|err| miette::miette!("invalid router config: {err}"))?;
            return Ok(Some(parsed));
        }
        return amber_mesh::decode_config_b64(trimmed)
            .map(Some)
            .map_err(|err| miette::miette!("invalid router config: {err}"));
    }

    if let Ok(b64) = std::env::var("AMBER_ROUTER_CONFIG_B64") {
        return amber_mesh::decode_config_b64(&b64)
            .map(Some)
            .map_err(|err| miette::miette!("invalid router config: {err}"));
    }

    if let Ok(raw) = std::env::var("AMBER_ROUTER_CONFIG_JSON") {
        let parsed = serde_json::from_str(&raw)
            .map_err(|err| miette::miette!("invalid router config: {err}"))?;
        return Ok(Some(parsed));
    }

    Ok(None)
}

pub(crate) fn apply_router_control_override(proxy: &mut ProxyCommand, value: &str) -> Result<()> {
    if let Some(path) = value.strip_prefix("unix://") {
        let path = path.trim();
        if path.is_empty() || !Path::new(path).is_absolute() {
            return Err(miette::miette!(
                "invalid --router-control-addr {}; expected unix:///absolute/path",
                value
            ));
        }
        proxy.set_router_control_unix(path)?;
    } else {
        proxy.set_router_control_tcp(value)?;
    }
    Ok(())
}

pub(crate) fn parse_named_socket_addr(value: &str, flag: &str) -> Result<(String, SocketAddr)> {
    let (name, addr) = value.split_once('=').ok_or_else(|| {
        miette::miette!("invalid {} value {}; expected NAME=ADDR:PORT", flag, value)
    })?;
    let name = name.trim();
    if name.is_empty() {
        return Err(miette::miette!(
            "invalid {} value {}; name must not be empty",
            flag,
            value
        ));
    }
    let addr = addr.trim().parse::<SocketAddr>().map_err(|err| {
        miette::miette!(
            "invalid {} value {}; address must be ADDR:PORT ({})",
            flag,
            value,
            err
        )
    })?;
    if addr.port() == 0 {
        return Err(miette::miette!(
            "invalid {} value {}; port must be non-zero",
            flag,
            value
        ));
    }
    Ok((name.to_string(), addr))
}

#[derive(Default)]
pub(crate) struct DenySet {
    deny_warnings: bool,
    deny_codes: BTreeSet<String>,
}

impl DenySet {
    pub(crate) fn new(deny: &[String]) -> Self {
        let mut set = Self::default();
        for d in deny {
            if d == "warnings" {
                set.deny_warnings = true;
            } else {
                set.deny_codes.insert(d.clone());
            }
        }
        set
    }

    fn is_denied(&self, code: &str) -> bool {
        self.deny_warnings || self.deny_codes.contains(code)
    }
}

pub(crate) fn print_diagnostics(diagnostics: &[miette::Report], deny: &DenySet) -> Result<bool> {
    let mut has_error = false;
    let handler = GraphicalReportHandler::new();

    for report in diagnostics {
        let diagnostic: &dyn Diagnostic = &**report;
        let code = diagnostic.code().map(|c| c.to_string()).unwrap_or_default();
        let severity = diagnostic.severity().unwrap_or(Severity::Error);
        let denied = matches!(severity, Severity::Warning) && deny.is_denied(&code);
        let is_error = denied || matches!(severity, Severity::Error);
        if is_error {
            has_error = true;
        }

        if denied {
            let denied_by = if deny.deny_warnings {
                "-D warnings".to_string()
            } else if code.is_empty() {
                "-D <lint>".to_string()
            } else {
                format!("-D {code}")
            };
            let denied = DeniedDiagnostic {
                inner: diagnostic,
                denied_by,
            };
            render_report(&handler, &denied)?;
        } else {
            render_report(&handler, diagnostic)?;
        }
    }

    Ok(has_error)
}

pub(crate) fn render_report(
    handler: &GraphicalReportHandler,
    diagnostic: &dyn Diagnostic,
) -> Result<()> {
    let mut out = String::new();
    handler
        .render_report(&mut out, diagnostic)
        .map_err(|_| miette::miette!("failed to render diagnostics"))?;
    eprint!("{out}");
    Ok(())
}

#[derive(Debug)]
pub(crate) struct DeniedDiagnostic<'a> {
    inner: &'a dyn Diagnostic,
    denied_by: String,
}

impl fmt::Display for DeniedDiagnostic<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.inner, f)
    }
}

impl std::error::Error for DeniedDiagnostic<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

impl Diagnostic for DeniedDiagnostic<'_> {
    fn code<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.inner.code()
    }

    fn severity(&self) -> Option<Severity> {
        Some(Severity::Error)
    }

    fn help<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        let hint = format!(
            "warning treated as error because it was denied via `{}`",
            self.denied_by
        );
        match self.inner.help() {
            Some(inner) => Some(Box::new(format!("{hint}\n{inner}"))),
            None => Some(Box::new(hint)),
        }
    }

    fn url<'a>(&'a self) -> Option<Box<dyn fmt::Display + 'a>> {
        self.inner.url()
    }

    fn source_code(&self) -> Option<&dyn miette::SourceCode> {
        self.inner.source_code()
    }

    fn labels(&self) -> Option<Box<dyn Iterator<Item = miette::LabeledSpan> + '_>> {
        self.inner.labels()
    }

    fn related<'a>(&'a self) -> Option<Box<dyn Iterator<Item = &'a dyn Diagnostic> + 'a>> {
        self.inner.related()
    }

    fn diagnostic_source(&self) -> Option<&dyn Diagnostic> {
        self.inner.diagnostic_source()
    }
}

pub(crate) fn parse_manifest_ref(input: &str) -> Result<ManifestRef> {
    if let Ok(r) = input.parse::<ManifestRef>()
        && r.url.as_url().is_some()
    {
        return Ok(r);
    }

    let abs = canonicalize_user_path(Path::new(input), "manifest path")?;
    let abs = resolve_manifest_entry_path(&abs)?;
    let url = url::Url::from_file_path(&abs)
        .map_err(|_| miette::miette!("could not convert `{}` into a file URL", abs.display()))?;

    Ok(ManifestRef::from_url(url))
}

pub(crate) struct ResolvedInput {
    pub(crate) manifest: ManifestRef,
    pub(crate) resolver: Resolver,
    pub(crate) registry: ResolverRegistry,
}

pub(crate) enum CompileInput {
    Manifest(ResolvedInput),
    ScenarioIr(CompiledScenario),
}

pub(crate) async fn resolve_compile_input(input: &str) -> Result<CompileInput> {
    if let Some(path) = local_input_path(input)?
        && let Some(compiled) = load_compiled_scenario_ir(&path)?
    {
        return Ok(CompileInput::ScenarioIr(compiled));
    }

    resolve_input(input).await.map(CompileInput::Manifest)
}

pub(crate) async fn resolve_input(input: &str) -> Result<ResolvedInput> {
    if let Some(path) = local_input_path(input)?
        && let Some(loader) = BundleLoader::from_path(&path)?
    {
        let bundle = loader.load().await?;
        return Ok(ResolvedInput {
            manifest: bundle.root,
            resolver: bundle.resolver,
            registry: bundle.registry,
        });
    }

    let manifest = parse_manifest_ref(input)?;
    Ok(ResolvedInput {
        manifest,
        resolver: Resolver::new(),
        registry: ResolverRegistry::default(),
    })
}

pub(crate) fn load_compiled_scenario_ir(path: &Path) -> Result<Option<CompiledScenario>> {
    if !path.is_file() {
        return Ok(None);
    }

    let bytes = fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read Scenario IR input `{}`", path.display()))?;
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    let Some(obj) = value.as_object() else {
        return Ok(None);
    };
    let Some(schema) = obj.get("schema").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    if schema != SCENARIO_IR_SCHEMA {
        return Ok(None);
    }

    let ir: ScenarioIr = serde_json::from_value(value)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid Scenario IR input `{}`", path.display()))?;
    CompiledScenario::from_ir(ir)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid Scenario IR input `{}`", path.display()))
        .map(Some)
}

pub(crate) fn is_run_plan_file(path: &Path) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }

    let bytes = fs::read(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read run plan candidate `{}`", path.display()))?;
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    let Some(obj) = value.as_object() else {
        return Ok(false);
    };
    Ok(obj.get("schema").and_then(serde_json::Value::as_str) == Some(RUN_PLAN_SCHEMA))
}

pub(crate) fn local_input_path(input: &str) -> Result<Option<PathBuf>> {
    if let Ok(url) = Url::parse(input) {
        if url.scheme() == "file" {
            let path = url
                .to_file_path()
                .map_err(|_| miette::miette!("could not convert `{input}` into a file path"))?;
            if !path.exists() {
                return Ok(None);
            }
            return canonicalize_user_path(&path, "input path").map(Some);
        }
        return Ok(None);
    }

    let path = Path::new(input);
    if !path.exists() {
        return Ok(None);
    }
    canonicalize_user_path(path, "input path").map(Some)
}

pub(crate) enum ArtifactOutput {
    Stdout,
    File(PathBuf),
}

pub(crate) struct OutputPaths {
    pub(crate) primary: Option<PathBuf>,
    pub(crate) run_plan: Option<PathBuf>,
    pub(crate) dot: Option<ArtifactOutput>,
    pub(crate) docker_compose: Option<PathBuf>,
    pub(crate) metadata: Option<ArtifactOutput>,
    pub(crate) kubernetes: Option<PathBuf>,
    pub(crate) direct: Option<PathBuf>,
    pub(crate) vm: Option<PathBuf>,
}

pub(crate) fn ensure_outputs_requested(args: &CompileArgs) -> Result<()> {
    if args.output.is_some()
        || args.run_plan.is_some()
        || args.dot.is_some()
        || args.docker_compose.is_some()
        || args.metadata.is_some()
        || args.bundle.is_some()
        || args.kubernetes.is_some()
        || args.direct.is_some()
        || args.vm.is_some()
    {
        return Ok(());
    }

    Err(miette::miette!(
        help = "Request at least one output with `--output`, `--run-plan`, `--dot`, \
                `--docker-compose`, `--metadata`, `--kubernetes`, `--direct`, `--vm`, or \
                `--bundle`.",
        "no outputs requested for `amber compile`"
    ))
}

pub(crate) fn resolve_output_paths(args: &CompileArgs) -> Result<OutputPaths> {
    let primary = args.output.clone();
    let run_plan = args.run_plan.clone();
    let dot = resolve_optional_output(&args.dot);
    let docker_compose = args.docker_compose.clone();
    let metadata = resolve_optional_output(&args.metadata);
    let kubernetes = args.kubernetes.clone();
    let direct = args.direct.clone();
    let vm = args.vm.clone();

    let file_outputs = [
        ("primary output", primary.as_deref()),
        ("run plan output", run_plan.as_deref()),
        ("dot output", artifact_file_path(dot.as_ref())),
        ("metadata output", artifact_file_path(metadata.as_ref())),
    ];
    for (index, (left_name, left_path)) in file_outputs.iter().enumerate() {
        let Some(left_path) = left_path else {
            continue;
        };
        for (right_name, right_path) in file_outputs.iter().skip(index + 1) {
            if right_path.is_some_and(|right_path| right_path == *left_path) {
                return Err(miette::miette!(
                    "{} path `{}` must not match {} path",
                    left_name,
                    left_path.display(),
                    right_name
                ));
            }
        }
    }

    let directory_outputs = [
        ("docker compose output directory", docker_compose.as_ref()),
        ("kubernetes output directory", kubernetes.as_ref()),
        ("direct output directory", direct.as_ref()),
        ("vm output directory", vm.as_ref()),
    ];
    for (name, dir) in [
        ("docker compose output directory", docker_compose.as_ref()),
        ("kubernetes output directory", kubernetes.as_ref()),
        ("direct output directory", direct.as_ref()),
        ("vm output directory", vm.as_ref()),
    ] {
        let Some(dir) = dir else {
            continue;
        };
        for (file_name, file_path) in file_outputs {
            if file_path.is_some_and(|file_path| file_path == dir.as_path()) {
                return Err(miette::miette!(
                    "{} `{}` must not match {} path",
                    name,
                    dir.display(),
                    file_name
                ));
            }
        }
    }

    for (index, (left_name, left_dir)) in directory_outputs.iter().enumerate() {
        let Some(left_dir) = left_dir else {
            continue;
        };
        for (right_name, right_dir) in directory_outputs.iter().skip(index + 1) {
            if right_dir.is_some_and(|right_dir| right_dir == *left_dir) {
                return Err(miette::miette!(
                    "{} `{}` must not match {}",
                    left_name,
                    left_dir.display(),
                    right_name
                ));
            }
        }
    }

    Ok(OutputPaths {
        primary,
        run_plan,
        dot,
        docker_compose,
        metadata,
        kubernetes,
        direct,
        vm,
    })
}

pub(crate) fn resolve_optional_output(request: &Option<PathBuf>) -> Option<ArtifactOutput> {
    request.as_ref().map(|path| {
        if path.as_path() == Path::new("-") {
            ArtifactOutput::Stdout
        } else {
            ArtifactOutput::File(path.clone())
        }
    })
}

pub(crate) fn artifact_file_path(output: Option<&ArtifactOutput>) -> Option<&Path> {
    match output {
        Some(ArtifactOutput::File(path)) => Some(path.as_path()),
        _ => None,
    }
}

pub(crate) fn canonicalize_user_path(path: &Path, context: &str) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().into_diagnostic()?.join(path)
    };
    path.canonicalize()
        .map_err(|err| miette::miette!("failed to resolve {context} `{}`: {err}", path.display()))
}

pub(crate) fn resolve_bundle_root(args: &CompileArgs) -> Result<Option<PathBuf>> {
    Ok(args.bundle.clone())
}

pub(crate) fn prepare_bundle_dir(path: &Path) -> Result<()> {
    if path.exists() {
        return Err(miette::miette!(
            "bundle output directory `{}` already exists; please delete it first",
            path.display()
        ));
    }

    std::fs::create_dir_all(path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create bundle directory `{}`", path.display()))?;
    Ok(())
}

pub(crate) fn write_primary_output(path: &Path, compiled: &CompiledScenario) -> Result<()> {
    let ir = ScenarioIrReporter
        .emit(compiled)
        .map_err(miette::Report::new)?;
    write_artifact(path, ir.as_bytes())
        .wrap_err_with(|| format!("failed to write primary output `{}`", path.display()))
}

pub(crate) fn write_run_plan_output(path: &Path, run_plan: &RunPlan) -> Result<()> {
    let json = serde_json::to_vec_pretty(run_plan)
        .map_err(|err| miette::miette!("failed to serialize run plan: {err}"))?;
    write_artifact(path, &json)
        .wrap_err_with(|| format!("failed to write run plan output `{}`", path.display()))
}

pub(crate) fn load_placement_file(path: Option<&Path>) -> Result<Option<PlacementFile>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let path = canonicalize_user_path(path, "placement file")?;
    let contents = fs::read_to_string(&path)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to read placement file `{}`", path.display()))?;
    parse_placement_file(&contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("invalid placement file `{}`", path.display()))
        .map(Some)
}

pub(crate) fn write_artifact(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to create directory `{}`", parent.display()))?;
    }

    std::fs::write(path, contents)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to write `{}`", path.display()))
}

pub(crate) fn write_unmanaged_export_output(
    root: &Path,
    run_plan: &RunPlan,
    kind: SiteKind,
) -> Result<()> {
    let export = build_unmanaged_export(run_plan, kind)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "failed to derive unmanaged {} export from the resolved run plan",
                unmanaged_export_label(kind)
            )
        })?;
    write_directory_output(
        root,
        unmanaged_export_output_dir_label(kind),
        &export.files,
        unmanaged_export_executable_rel_path(kind),
    )
}

pub(crate) fn write_directory_output(
    root: &Path,
    label: &str,
    files: &BTreeMap<PathBuf, String>,
    executable_rel_path: Option<&Path>,
) -> Result<()> {
    if root.exists() {
        if root.is_dir() {
            std::fs::remove_dir_all(root)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to remove {label} `{}`", root.display()))?;
        } else {
            return Err(miette::miette!(
                "{} `{}` is not a directory",
                label,
                root.display()
            ));
        }
    }

    std::fs::create_dir_all(root)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create {label} `{}`", root.display()))?;

    for (rel_path, content) in files {
        let full_path = root.join(rel_path);
        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to create directory `{}`", parent.display()))?;
        }
        std::fs::write(&full_path, content)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to write `{}`", full_path.display()))?;
        #[cfg(unix)]
        if executable_rel_path.is_some_and(|expected| rel_path.as_path() == expected) {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = std::fs::metadata(&full_path)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to stat `{}`", full_path.display()))?
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&full_path, perms)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to chmod `{}`", full_path.display()))?;
        }
    }

    Ok(())
}

pub(crate) fn unmanaged_export_label(kind: SiteKind) -> &'static str {
    match kind {
        SiteKind::Compose => "docker-compose",
        SiteKind::Kubernetes => "kubernetes",
        SiteKind::Direct => "direct",
        SiteKind::Vm => "vm",
    }
}

pub(crate) fn unmanaged_export_output_dir_label(kind: SiteKind) -> &'static str {
    match kind {
        SiteKind::Compose => "docker compose output directory",
        SiteKind::Kubernetes => "kubernetes output directory",
        SiteKind::Direct => "direct output directory",
        SiteKind::Vm => "vm output directory",
    }
}

pub(crate) fn unmanaged_export_executable_rel_path(kind: SiteKind) -> Option<&'static Path> {
    match kind {
        SiteKind::Direct | SiteKind::Vm => Some(Path::new(RUN_SCRIPT_FILENAME)),
        SiteKind::Compose | SiteKind::Kubernetes => None,
    }
}
