use std::collections::BTreeSet;

use amber_config as rc;
use amber_scenario::Scenario;

use super::ReporterError;
use crate::targets::{
    mesh::{
        plan::{MeshPlan, component_label},
        proxy_metadata::collect_external_slot_metadata,
    },
    program_config::ConfigPlan,
};

pub(crate) const GENERATED_README_FILENAME: &str = "README.md";
pub(crate) const GENERATED_ENV_SAMPLE_FILENAME: &str = "env.example";
pub(crate) const GENERATED_COMPOSE_FILENAME: &str = "compose.yaml";

#[derive(Clone, Debug)]
pub(crate) struct ExecutionGuide {
    root_inputs: Vec<GuideRootInput>,
    external_slots: Vec<GuideExternalSlot>,
    exports: Vec<GuideExport>,
}

#[derive(Clone, Debug)]
struct GuideRootInput {
    path: String,
    env_var: String,
    required: bool,
    secret: bool,
}

#[derive(Clone, Debug)]
struct GuideExternalSlot {
    name: String,
    env_var: String,
    required: bool,
    kind: String,
}

#[derive(Clone, Debug)]
struct GuideExport {
    name: String,
    component: String,
    protocol: String,
}

pub(crate) fn build_execution_guide(
    scenario: &Scenario,
    mesh_plan: &MeshPlan,
    config_plan: &ConfigPlan,
) -> Result<ExecutionGuide, ReporterError> {
    let runtime_root_paths = runtime_root_paths(config_plan);
    let mut root_inputs = Vec::new();
    if let Some(schema) = scenario.component(scenario.root).config_schema.as_ref() {
        let mut leaves = rc::collect_leaf_paths(schema).map_err(|err| {
            ReporterError::new(format!("failed to enumerate config inputs: {err}"))
        })?;
        leaves.retain(|leaf| runtime_root_paths.contains(&leaf.path));
        for leaf in leaves {
            let env_var = rc::env_var_for_path(&leaf.path)
                .map_err(|err| ReporterError::new(format!("failed to map config path: {err}")))?;
            root_inputs.push(GuideRootInput {
                path: leaf.path,
                env_var,
                required: leaf.required,
                secret: leaf.secret,
            });
        }
    }
    root_inputs.sort_by(|left, right| left.path.cmp(&right.path));

    let mut external_slots: Vec<_> = collect_external_slot_metadata(scenario, mesh_plan)
        .into_iter()
        .map(|(name, meta)| GuideExternalSlot {
            name,
            env_var: meta.url_env,
            required: meta.required,
            kind: meta.kind,
        })
        .collect();
    external_slots.sort_by(|left, right| left.name.cmp(&right.name));

    let mut exports: Vec<_> = mesh_plan
        .exports
        .iter()
        .map(|export| GuideExport {
            name: export.name.clone(),
            component: component_label(scenario, export.provider),
            protocol: export.endpoint.protocol.to_string(),
        })
        .collect();
    exports.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(ExecutionGuide {
        root_inputs,
        external_slots,
        exports,
    })
}

fn runtime_root_paths(config_plan: &ConfigPlan) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for view in config_plan.runtime_views.values() {
        out.extend(view.allowed_root_leaf_paths.iter().cloned());
    }
    for plan in config_plan.program_plans.values() {
        if let Some(image) = plan.image() {
            image.collect_runtime_root_paths(&mut out);
        }
    }
    out
}

impl ExecutionGuide {
    pub(crate) fn has_root_inputs(&self) -> bool {
        !self.root_inputs.is_empty()
    }

    pub(crate) fn has_external_slots(&self) -> bool {
        !self.external_slots.is_empty()
    }

    pub(crate) fn has_exports(&self) -> bool {
        !self.exports.is_empty()
    }

    pub(crate) fn render_env_sample(&self, include_external_slots: bool, backend: &str) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "# Amber runtime inputs for the generated {backend} output.\n"
        ));
        out.push_str(
            "# Fill in the values you need, then pass this file to the runtime command.\n",
        );

        if self.root_inputs.is_empty()
            && (!include_external_slots || self.external_slots.is_empty())
        {
            out.push_str("# No env-based runtime inputs are required for this output.\n");
            return out;
        }

        if !self.root_inputs.is_empty() {
            out.push_str("\n# Root config inputs\n");
            for input in &self.root_inputs {
                let required = if input.required {
                    "required"
                } else {
                    "optional"
                };
                let secret = if input.secret { "secret" } else { "config" };
                out.push_str(&format!(
                    "# {required} {secret} config.{}\n{}=\n",
                    input.path, input.env_var
                ));
            }
        }

        if include_external_slots && !self.external_slots.is_empty() {
            out.push_str("\n# External slot URLs\n");
            for slot in &self.external_slots {
                let required = if slot.required {
                    "required"
                } else {
                    "optional"
                };
                out.push_str(&format!(
                    "# {required} {} slot {}\n{}=\n",
                    slot.kind, slot.name, slot.env_var
                ));
            }
        }

        out
    }

    pub(crate) fn render_compose_readme(&self) -> String {
        let mut out = String::new();
        out.push_str("# Amber Docker Compose Run Guide\n\n");
        out.push_str("> Generated by Amber. Do not edit by hand.\n\n");
        out.push_str(
            "This directory contains `compose.yaml`, `env.example`, and `README.md` for a Docker \
             Compose runtime generated by Amber.\n",
        );
        out.push_str("\n## Quickstart\n\n");
        let start_step = if self.has_root_inputs() { 2 } else { 1 };
        let proxy_step = start_step + 1;
        if self.has_root_inputs() {
            out.push_str("1. Copy `env.example` to `.env` and fill in these values:\n\n");
            push_root_inputs_markdown(&mut out, self);
            out.push_str("\n```sh\n");
            out.push_str(&format!(
                "cp {} .env\n$EDITOR .env\n",
                GENERATED_ENV_SAMPLE_FILENAME,
            ));
            out.push_str("```\n\n");
        }
        out.push_str(&format!("{start_step}. Start the stack:\n\n"));
        out.push_str("```sh\ndocker compose up -d\n```\n");

        if self.has_exports() || self.has_external_slots() {
            out.push('\n');
            out.push_str(&format!("{proxy_step}. In another terminal, run:\n\n"));
            out.push_str("```sh\n");
            out.push_str(&render_proxy_command(
                ".",
                &self.external_slots,
                &self.exports,
                ProxyCommandStyle::Compose,
                ProxyCommandMode::Template,
            ));
            out.push_str("\n```\n\n");
            if self.has_external_slots() {
                out.push_str(
                    "Fill in the address of each local service that this scenario needs to \
                     call:\n\n",
                );
                push_local_slot_targets_markdown(&mut out, &self.external_slots);
                out.push('\n');
            }
            if self.has_exports() {
                out.push_str(
                    "Choose a free local port for each scenario endpoint you want `amber proxy` \
                     to expose:\n\n",
                );
                push_local_export_endpoints_markdown(&mut out, &self.exports);
                out.push('\n');
            }
            out.push_str("Example:\n\n```sh\n");
            out.push_str(&render_proxy_command(
                ".",
                &self.external_slots,
                &self.exports,
                ProxyCommandStyle::Compose,
                ProxyCommandMode::Example,
            ));
            out.push_str("\n```\n\n");
            out.push_str("If you use a custom Compose project name:\n\n```sh\n");
            out.push_str("docker compose -p my-scenario up -d\n");
            out.push_str(&render_proxy_command_with_project_name(
                ".",
                &self.external_slots,
                &self.exports,
                ProxyCommandStyle::Compose,
                ProxyCommandMode::Example,
                Some("my-scenario"),
            ));
            out.push_str("\n```\n");
        }

        out.push_str("\n## Teardown\n\n```sh\ndocker compose down -v\n```\n");
        out
    }

    pub(crate) fn render_direct_readme(&self, has_router_env_file: bool) -> String {
        let mut out = String::new();
        out.push_str("# Amber Direct Run Guide\n\n");
        out.push_str("> Generated by Amber. Do not edit by hand.\n\n");
        if self.has_root_inputs() {
            out.push_str(
                "This directory contains `direct-plan.json`, `run.sh`, `env.example`, and \
                 `README.md` for a direct/native runtime generated by Amber.\n",
            );
        } else if has_router_env_file {
            out.push_str(
                "This directory contains `direct-plan.json`, `run.sh`, `router-external.env`, and \
                 `README.md` for a direct/native runtime generated by Amber.\n",
            );
        } else {
            out.push_str(
                "This directory contains `direct-plan.json`, `run.sh`, and `README.md` for a \
                 direct/native runtime generated by Amber.\n",
            );
        }
        out.push_str("\n## Quickstart\n\n");
        let start_step = if self.has_root_inputs() { 2 } else { 1 };
        let proxy_step = start_step + 1;
        if self.has_root_inputs() {
            out.push_str("1. Copy `env.example` to `.env` and fill in these values:\n\n");
            push_root_inputs_markdown(&mut out, self);
            out.push_str("\n```sh\n");
            out.push_str(&format!(
                "cp {} .env\n$EDITOR .env\n",
                GENERATED_ENV_SAMPLE_FILENAME,
            ));
            out.push_str("```\n\n");
        }
        out.push_str(&format!("{start_step}. Start the runtime:\n\n"));
        out.push_str(
            "Linux requires `bwrap` and `slirp4netns`. macOS requires `/usr/bin/sandbox-exec`.\n\n",
        );
        out.push_str("```sh\n");
        if self.has_root_inputs() {
            out.push_str("set -a\n. ./.env\nset +a\n./run.sh\n");
        } else {
            out.push_str("./run.sh\n");
        }
        out.push_str("```\n");

        if self.has_exports() || self.has_external_slots() {
            out.push_str(&format!("\n{proxy_step}. In another terminal, run:\n\n"));
            out.push_str("```sh\n");
            out.push_str(&render_proxy_command(
                ".",
                &self.external_slots,
                &self.exports,
                ProxyCommandStyle::Direct,
                ProxyCommandMode::Template,
            ));
            out.push_str("\n```\n\n");
            if self.has_external_slots() {
                out.push_str(
                    "Fill in the address of each local service that this scenario needs to \
                     call:\n\n",
                );
                push_local_slot_targets_markdown(&mut out, &self.external_slots);
                out.push('\n');
                if has_router_env_file {
                    out.push_str(
                        "If you do not want to pass those service addresses through `amber \
                         proxy`, put them in `router-external.env` before you start \
                         `./run.sh`.\n\n",
                    );
                }
            }
            if self.has_exports() {
                out.push_str(
                    "Choose a free local port for each scenario endpoint you want `amber proxy` \
                     to expose:\n\n",
                );
                push_local_export_endpoints_markdown(&mut out, &self.exports);
                out.push('\n');
            }
            out.push_str("Example:\n\n```sh\n");
            out.push_str(&render_proxy_command(
                ".",
                &self.external_slots,
                &self.exports,
                ProxyCommandStyle::Direct,
                ProxyCommandMode::Example,
            ));
            out.push_str("\n```\n");
        }

        out.push_str(
            "\n## Teardown\n\nStop the direct runtime with `Ctrl-C` in the terminal running \
             `./run.sh`.\n",
        );
        out
    }

    pub(crate) fn render_kubernetes_readme(
        &self,
        namespace: &str,
        deployments: &[String],
        needs_router: bool,
    ) -> String {
        let mut out = String::new();
        out.push_str("# Amber Kubernetes Run Guide\n\n");
        out.push_str("> Generated by Amber. Do not edit by hand.\n\n");
        out.push_str(
            "This directory contains `kustomization.yaml` and any env samples needed for the \
             generated Kubernetes runtime.\n",
        );
        out.push_str("\n## Quickstart\n\n");
        let apply_step = if self.has_root_inputs() { 2 } else { 1 };
        let port_forward_step = apply_step + 1;
        let proxy_step = apply_step + 2;
        if self.has_root_inputs() {
            out.push_str("1. Fill the generated env files with these values:\n\n");
            push_root_inputs_markdown(&mut out, self);
            out.push('\n');
            out.push_str("```sh\n");
            if self.root_inputs.iter().any(|input| !input.secret) {
                out.push_str("$EDITOR root-config.env\n");
            }
            if self.root_inputs.iter().any(|input| input.secret) {
                out.push_str("$EDITOR root-config-secret.env\n");
            }
            out.push_str("```\n\n");
        }
        out.push_str(&format!(
            "{apply_step}. Apply the manifests and wait for the deployments:\n\n"
        ));
        out.push_str("```sh\nkubectl apply -k .\n");
        for deployment in deployments {
            out.push_str(&format!(
                "kubectl -n {} rollout status deploy/{}\n",
                namespace, deployment
            ));
        }
        out.push_str("```\n");

        if needs_router && (self.has_exports() || self.has_external_slots()) {
            out.push_str(&format!(
                "\n{port_forward_step}. Keep this port-forward running in one terminal:\n\n"
            ));
            out.push_str("```sh\n");
            out.push_str(&format!(
                "kubectl -n {} port-forward deploy/amber-router 24000:24000 24100:24100\n",
                namespace
            ));
            out.push_str("```\n\n");

            out.push_str(&format!("{proxy_step}. In another terminal, run:\n\n"));
            if self.has_external_slots() {
                out.push_str(
                    "Set `MESH_HOST` to an address that pods can use to reach your machine. On \
                     Docker Desktop, `host.docker.internal` usually works.\n\n",
                );
                out.push_str("```sh\nMESH_HOST=host.docker.internal\n");
                out.push_str(&render_proxy_command(
                    ".",
                    &self.external_slots,
                    &self.exports,
                    ProxyCommandStyle::Kubernetes,
                    ProxyCommandMode::Template,
                ));
                out.push_str("\n```\n\n");
                out.push_str(
                    "Fill in the address of each local service that this scenario needs to \
                     call:\n\n",
                );
                push_local_slot_targets_markdown(&mut out, &self.external_slots);
                out.push('\n');
                if self.has_exports() {
                    out.push_str(
                        "Choose a free local port for each scenario endpoint you want `amber \
                         proxy` to expose:\n\n",
                    );
                    push_local_export_endpoints_markdown(&mut out, &self.exports);
                    out.push('\n');
                }
                out.push_str("Example:\n\n```sh\nMESH_HOST=host.docker.internal\n");
                out.push_str(&render_proxy_command(
                    ".",
                    &self.external_slots,
                    &self.exports,
                    ProxyCommandStyle::Kubernetes,
                    ProxyCommandMode::Example,
                ));
                out.push_str("\n```\n");
            } else {
                out.push_str("```sh\n");
                out.push_str(&render_proxy_command(
                    ".",
                    &self.external_slots,
                    &self.exports,
                    ProxyCommandStyle::Kubernetes,
                    ProxyCommandMode::Template,
                ));
                out.push_str("\n```\n\n");
                if self.has_exports() {
                    out.push_str(
                        "Choose a free local port for each scenario endpoint you want `amber \
                         proxy` to expose:\n\n",
                    );
                    push_local_export_endpoints_markdown(&mut out, &self.exports);
                    out.push('\n');
                }
                out.push_str("Example:\n\n```sh\n");
                out.push_str(&render_proxy_command(
                    ".",
                    &self.external_slots,
                    &self.exports,
                    ProxyCommandStyle::Kubernetes,
                    ProxyCommandMode::Example,
                ));
                out.push_str("\n```\n");
            }
        }

        out.push_str("\n## Teardown\n\n```sh\nkubectl delete -k .\n```\n");
        out
    }
}

fn push_local_export_endpoints_markdown(out: &mut String, exports: &[GuideExport]) {
    for (index, export) in exports.iter().enumerate() {
        out.push_str(&format!(
            "- `{}`: forwards to `{}` (`{}`). Example: `127.0.0.1:{}`\n",
            export.name,
            export.component,
            export.protocol,
            18080 + index,
        ));
    }
}

fn push_local_slot_targets_markdown(out: &mut String, slots: &[GuideExternalSlot]) {
    for (index, slot) in slots.iter().enumerate() {
        out.push_str(&format!(
            "- `{}`: address of the `{}` service. Example: `127.0.0.1:{}`\n",
            slot.name,
            slot.kind,
            8081 + index
        ));
    }
}

fn push_root_inputs_markdown(out: &mut String, guide: &ExecutionGuide) {
    for input in &guide.root_inputs {
        let required = if input.required {
            "required"
        } else {
            "optional"
        };
        let secret = if input.secret { "secret" } else { "config" };
        out.push_str(&format!(
            "- `{}`: {} {} value for `config.{}`\n",
            input.env_var, required, secret, input.path
        ));
    }
}

enum ProxyCommandStyle {
    Compose,
    Direct,
    Kubernetes,
}

enum ProxyCommandMode {
    Template,
    Example,
}

fn render_proxy_command(
    output_ref: &str,
    slots: &[GuideExternalSlot],
    exports: &[GuideExport],
    style: ProxyCommandStyle,
    mode: ProxyCommandMode,
) -> String {
    render_proxy_command_with_project_name(output_ref, slots, exports, style, mode, None)
}

fn render_proxy_command_with_project_name(
    output_ref: &str,
    slots: &[GuideExternalSlot],
    exports: &[GuideExport],
    style: ProxyCommandStyle,
    mode: ProxyCommandMode,
    project_name: Option<&str>,
) -> String {
    let mut lines = vec![format!("amber proxy {output_ref}")];
    if let Some(project_name) = project_name {
        lines.push(format!("  --project-name {project_name}"));
    }

    for (index, slot) in slots.iter().enumerate() {
        let value = match mode {
            ProxyCommandMode::Template => format!("<address-for-{}>", slot.name),
            ProxyCommandMode::Example => format!("127.0.0.1:{}", 8081 + index),
        };
        lines.push(format!("  --slot {}={value}", slot.name));
    }
    for (index, export) in exports.iter().enumerate() {
        let value = match mode {
            ProxyCommandMode::Template => format!("127.0.0.1:<free-port-for-{}>", export.name),
            ProxyCommandMode::Example => format!("127.0.0.1:{}", 18080 + index),
        };
        lines.push(format!("  --export {}={}", export.name, value));
    }

    match style {
        ProxyCommandStyle::Compose | ProxyCommandStyle::Direct => {}
        ProxyCommandStyle::Kubernetes => {
            if !slots.is_empty() {
                lines.push("  --mesh-addr \"${MESH_HOST}:25000\"".to_string());
            }
            lines.push("  --router-addr 127.0.0.1:24000".to_string());
            lines.push("  --router-control-addr 127.0.0.1:24100".to_string());
        }
    }

    if lines.len() == 1 {
        return lines.remove(0);
    }

    let mut out = String::new();
    for (index, line) in lines.iter().enumerate() {
        if index == 0 {
            out.push_str(line);
        } else {
            out.push_str(" \\\n");
            out.push_str(line);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_guide() -> ExecutionGuide {
        ExecutionGuide {
            root_inputs: vec![
                GuideRootInput {
                    path: "api.key".to_string(),
                    env_var: "AMBER_CONFIG_API__KEY".to_string(),
                    required: true,
                    secret: true,
                },
                GuideRootInput {
                    path: "api.base_url".to_string(),
                    env_var: "AMBER_CONFIG_API__BASE_URL".to_string(),
                    required: false,
                    secret: false,
                },
            ],
            external_slots: vec![GuideExternalSlot {
                name: "upstream".to_string(),
                env_var: "AMBER_EXTERNAL_SLOT_UPSTREAM_URL".to_string(),
                required: true,
                kind: "http".to_string(),
            }],
            exports: vec![GuideExport {
                name: "public".to_string(),
                component: "/green".to_string(),
                protocol: "http".to_string(),
            }],
        }
    }

    #[test]
    fn compose_env_sample_mentions_root_inputs_and_slots() {
        let env = sample_guide().render_env_sample(true, "docker-compose");
        assert!(env.contains("AMBER_CONFIG_API__KEY="), "{env}");
        assert!(env.contains("AMBER_EXTERNAL_SLOT_UPSTREAM_URL="), "{env}");
    }

    #[test]
    fn compose_readme_mentions_env_file_and_proxy_command() {
        let readme = sample_guide().render_compose_readme();
        assert!(readme.contains("## Quickstart"), "{readme}");
        assert!(readme.contains("Generated by Amber. Do not edit by hand."));
        assert!(readme.contains("cp env.example .env"));
        assert!(readme.contains("docker compose up -d"));
        assert!(
            readme
                .contains("- `AMBER_CONFIG_API__KEY`: required secret value for `config.api.key`")
        );
        assert!(
            readme
                .contains("- `upstream`: address of the `http` service. Example: `127.0.0.1:8081`")
        );
        assert!(
            readme
                .contains("- `public`: forwards to `/green` (`http`). Example: `127.0.0.1:18080`")
        );
        assert!(readme.contains("--slot upstream=<address-for-upstream>"));
        assert!(readme.contains("--export public=127.0.0.1:<free-port-for-public>"));
        assert!(readme.contains(
            "Example:\n\n```sh\namber proxy . \\\n  --slot upstream=127.0.0.1:8081 \\\n  --export \
             public=127.0.0.1:18080"
        ));
        assert!(readme.contains("--project-name my-scenario"));
        assert!(readme.contains("Fill in the address of each local service"));
        assert!(readme.contains("amber proxy ."));
    }

    #[test]
    fn direct_readme_uses_quickstart_and_proxy_command() {
        let readme = sample_guide().render_direct_readme(true);
        assert!(readme.contains("./run.sh"), "{readme}");
        assert!(
            readme.contains("Generated by Amber. Do not edit by hand."),
            "{readme}"
        );
        assert!(readme.contains("cp env.example .env"), "{readme}");
        assert!(readme.contains(". ./.env"), "{readme}");
        assert!(
            readme.contains("--slot upstream=<address-for-upstream>"),
            "{readme}"
        );
        assert!(
            readme
                .contains("- `public`: forwards to `/green` (`http`). Example: `127.0.0.1:18080`"),
            "{readme}"
        );
    }

    #[test]
    fn kubernetes_readme_mentions_port_forward_and_proxy_flags() {
        let readme = sample_guide().render_kubernetes_readme(
            "scenario-test",
            &["amber-router".to_string(), "c0-component".to_string()],
            true,
        );
        assert!(readme.contains("Generated by Amber. Do not edit by hand."));
        assert!(readme.contains("kubectl -n scenario-test port-forward deploy/amber-router"));
        assert!(readme.contains("--router-control-addr 127.0.0.1:24100"));
        assert!(readme.contains("--mesh-addr \"${MESH_HOST}:25000\""));
        assert!(
            readme
                .contains("- `upstream`: address of the `http` service. Example: `127.0.0.1:8081`")
        );
        assert!(
            readme
                .contains("- `public`: forwards to `/green` (`http`). Example: `127.0.0.1:18080`")
        );
    }
}
