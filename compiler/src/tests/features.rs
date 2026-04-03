use amber_scenario::{TemplateBinding, TemplateConfigField};

use super::*;

#[tokio::test]
async fn delegated_export_chain_resolves_binding_source() {
    let dir = tmp_dir("scenario-delegated-export-chain");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");
    let grand_path = dir.path().join("grand.json5");
    let consumer_path = dir.path().join("consumer.json5");

    write_file(
        &grand_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "grand",
            entrypoint: ["grand"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
          exports: { api: "api" },
        }
        "#,
    );
    write_file(
        &child_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                grand: "{grand}",
              }},
              exports: {{ api: "#grand.api" }},
            }}
            "##,
            grand = file_url(&grand_path),
        ),
    );
    write_file(
        &consumer_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                child: "{child}",
                consumer: "{consumer}",
              }},
              bindings: [
                {{ to: "#consumer.api", from: "#child.api" }},
              ],
            }}
            "##,
            child = file_url(&child_path),
            consumer = file_url(&consumer_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let compilation = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    let consumer_id = compilation
        .scenario
        .components_iter()
        .find(|(_, c)| c.moniker.as_str() == "/consumer")
        .map(|(id, _)| id)
        .expect("consumer component");

    let binding = compilation
        .scenario
        .bindings
        .iter()
        .find(|b| b.to.component == consumer_id && b.to.name == "api")
        .expect("binding");
    let from = match &binding.from {
        BindingFrom::Component(from) => from,
        BindingFrom::Resource(resource) => {
            panic!(
                "unexpected resource binding resources:{}:{}",
                graph::component_path_for(&compilation.scenario.components, resource.component),
                resource.name
            )
        }
        BindingFrom::Framework(name) => {
            panic!("unexpected framework binding framework.{name}")
        }
        BindingFrom::External(slot) => {
            panic!("unexpected external binding slots.{}", slot.name)
        }
    };
    let from_path = graph::component_path_for(&compilation.scenario.components, from.component);
    assert_eq!(from_path, "/child/grand");
    assert_eq!(from.name, "api");
}

#[tokio::test]
async fn scenario_ir_omits_component_exports_for_pruned_child_branches() {
    let root_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("examples")
        .join("tau2")
        .join("scenario.json5")
        .canonicalize()
        .unwrap();

    let compilation = default_compiler()
        .compile(
            manifest_ref_for_path(&root_path),
            optimized_compile_options(),
        )
        .await
        .unwrap();

    let compiled = compiled_scenario(&compilation);
    let green_router = compiled
        .scenario_ir()
        .components
        .iter()
        .find(|component| component.moniker == "/green_router")
        .expect("green_router component should exist in Scenario IR");

    assert_eq!(
        green_router.exports,
        BTreeMap::from([(
            "llm".to_string(),
            amber_scenario::ir::ComponentExportTargetIr::ChildExport {
                child: "proxy".to_string(),
                export: "llm".to_string(),
            },
        )])
    );

    let purple_router = compiled
        .scenario_ir()
        .components
        .iter()
        .find(|component| component.moniker == "/purple_router")
        .expect("purple_router component should exist in Scenario IR");
    assert!(
        purple_router.exports.contains_key("admin_api"),
        "live delegated exports should still be preserved in Scenario IR"
    );
}

pub(super) struct CountingBackend {
    calls: AtomicUsize,
}

impl CountingBackend {
    pub(super) fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }

    pub(super) fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

pub(super) struct StaticBackend {
    source: Arc<str>,
}

impl StaticBackend {
    pub(super) fn new(source: Arc<str>) -> Self {
        Self { source }
    }
}

impl Backend for StaticBackend {
    fn resolve_url<'a>(
        &'a self,
        url: &'a Url,
    ) -> Pin<Box<dyn Future<Output = Result<Resolution, amber_resolver::Error>> + Send + 'a>> {
        let url = url.clone();
        let source = Arc::clone(&self.source);

        Box::pin(async move {
            tokio::task::yield_now().await;
            let spans = Arc::new(amber_manifest::ManifestSpans::parse(&source));
            let manifest: Manifest = source.parse().unwrap();
            Ok(Resolution {
                url,
                manifest,
                source,
                spans,
                bundle_source: None,
            })
        })
    }
}

impl Backend for CountingBackend {
    fn resolve_url<'a>(
        &'a self,
        url: &'a Url,
    ) -> Pin<Box<dyn Future<Output = Result<Resolution, amber_resolver::Error>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let url = url.clone();

        Box::pin(async move {
            tokio::task::yield_now().await;
            let source: Arc<str> = r#"{ manifest_version: "0.1.0" }"#.into();
            let spans = Arc::new(amber_manifest::ManifestSpans::parse(&source));
            let manifest: Manifest = source.parse().unwrap();
            Ok(Resolution {
                url,
                manifest,
                source,
                spans,
                bundle_source: None,
            })
        })
    }
}

#[tokio::test]
async fn resolution_deduplicates_inflight_requests() {
    let dir = tmp_dir("scenario-inflight-dedup");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          components: {
            a: "count://same",
            b: "count://same",
          }
        }
        "#,
    );

    let backend = Arc::new(CountingBackend::new());
    let resolver = Resolver::new().with_remote(RemoteResolver::new(["count"], backend.clone()));

    let compiler = Compiler::new(resolver, DigestStore::default());
    let root_ref = manifest_ref_for_path(&root_path);

    let compilation = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);
    assert_eq!(backend.call_count(), 1);
}

#[tokio::test]
async fn resolution_environments_allow_parent_to_enable_resolvers_for_children() {
    let dir = tmp_dir("scenario-envs");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          environments: {
            counting: { resolvers: ["count"] },
          },
          components: {
            a: { manifest: "count://same", environment: "counting" },
            b: { manifest: "count://same", environment: "counting" },
          }
        }
        "#,
    );

    let backend = Arc::new(CountingBackend::new());
    let base_resolver = Resolver::new();

    let mut registry = ResolverRegistry::new();
    registry.insert("count", RemoteResolver::new(["count"], backend.clone()));

    let compiler = Compiler::new(base_resolver, DigestStore::default()).with_registry(registry);
    let root_ref = manifest_ref_for_path(&root_path);

    let compilation = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert_eq!(compilation.scenario.components.len(), 3);
    assert_eq!(backend.call_count(), 1);
}

#[tokio::test]
async fn child_template_selector_expands_into_sorted_frozen_catalog() {
    let dir = tmp_dir("scenario-child-template-selector");
    let root_path = dir.path().join("root.json5");
    let jobs_dir = dir.path().join("jobs");
    fs::create_dir_all(&jobs_dir).unwrap();
    let alpha_path = jobs_dir.join("alpha.json5");
    let beta_path = jobs_dir.join("beta.json5");
    let nested_dir = jobs_dir.join("nested");
    fs::create_dir_all(&nested_dir).unwrap();
    let leaf_path = nested_dir.join("leaf.json5");

    write_file(
        &alpha_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            realm: { kind: "component" },
          },
        }
        "#,
    );
    write_file(
        &leaf_path,
        r#"
        {
          manifest_version: "0.1.0",
        }
        "#,
    );
    write_file(
        &beta_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{
                realm: {{ kind: "component" }},
              }},
              components: {{
                leaf: "{leaf}",
              }},
            }}
            "##,
            leaf = file_url(&leaf_path),
        ),
    );
    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            realm: { kind: "component", optional: true },
          },
          child_templates: {
            worker: {
              allowed_manifests: {
                root: "./jobs",
                include: ["**/*.json5"],
              },
              bindings: {
                realm: "slots.realm",
              },
            },
          },
        }
        "#,
    );

    let compiler = default_compiler();
    let compilation = compiler
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap();

    let root = compilation.scenario.component(compilation.scenario.root);
    let template = root
        .child_templates
        .get("worker")
        .expect("child template should be linked");
    let allowed = template
        .allowed_manifests
        .as_ref()
        .expect("open template should carry allowed manifest keys");

    assert_eq!(
        allowed,
        &vec![
            file_url(&alpha_path).to_string(),
            file_url(&beta_path).to_string(),
            file_url(&leaf_path).to_string(),
        ]
    );
    assert_eq!(
        template.bindings.get("realm"),
        Some(&TemplateBinding::Prefilled {
            selector: "slots.realm".parse().unwrap(),
        })
    );
    assert!(template.manifest.is_none());
    assert!(template.config.is_empty());
    assert!(matches!(
        template.bindings.get("realm"),
        Some(TemplateBinding::Prefilled { .. })
    ));
    assert!(!matches!(
        template.config.get("realm"),
        Some(TemplateConfigField::Open { .. })
    ));

    let catalog_keys = compilation
        .scenario
        .manifest_catalog
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        catalog_keys,
        vec![
            file_url(&alpha_path).to_string(),
            file_url(&beta_path).to_string(),
            file_url(&leaf_path).to_string(),
        ]
    );
}

#[tokio::test]
async fn experimental_features_must_be_enabled_by_parent() {
    let dir = tmp_dir("scenario-experimental-parent");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["docker"],
        }
        "#,
    );

    write_file(
        &root_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              components: {{
                child: "{child}",
              }},
            }}
            "#,
            child = file_url(&child_path)
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let err = compiler
        .compile(root_ref, CompileOptions::default())
        .await
        .expect_err("missing parent experimental feature should fail");

    match err {
        crate::Error::Frontend(crate::frontend::Error::ExperimentalFeatureNotEnabled {
            child,
            missing_features,
            ..
        }) => {
            assert_eq!(child.as_ref(), "child");
            assert_eq!(missing_features.to_string(), "docker");
        }
        other => panic!("expected ExperimentalFeatureNotEnabled, got: {other}"),
    }
}

#[tokio::test]
async fn experimental_features_are_checked_per_edge() {
    let dir = tmp_dir("scenario-experimental-per-edge");
    let root_path = dir.path().join("root.json5");
    let parent_path = dir.path().join("parent.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["docker"],
        }
        "#,
    );

    write_file(
        &parent_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              components: {{
                leaf: "{child}",
              }},
            }}
            "#,
            child = file_url(&child_path)
        ),
    );

    write_file(
        &root_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["docker"],
              components: {{
                parent: "{parent}",
              }},
            }}
            "#,
            parent = file_url(&parent_path)
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let err = compiler
        .compile(root_ref, CompileOptions::default())
        .await
        .expect_err("intermediate parent missing feature should fail");

    match err {
        crate::Error::Frontend(crate::frontend::Error::ExperimentalFeatureNotEnabled {
            child,
            missing_features,
            ..
        }) => {
            assert_eq!(child.as_ref(), "leaf");
            assert_eq!(missing_features.to_string(), "docker");
        }
        other => panic!("expected ExperimentalFeatureNotEnabled, got: {other}"),
    }
}

#[tokio::test]
async fn experimental_features_succeed_when_enabled_on_every_parent() {
    let dir = tmp_dir("scenario-experimental-enabled");
    let root_path = dir.path().join("root.json5");
    let parent_path = dir.path().join("parent.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          experimental_features: ["docker"],
        }
        "#,
    );

    write_file(
        &parent_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["docker"],
              components: {{
                leaf: "{child}",
              }},
            }}
            "#,
            child = file_url(&child_path)
        ),
    );

    write_file(
        &root_path,
        &format!(
            r#"
            {{
              manifest_version: "0.1.0",
              experimental_features: ["docker"],
              components: {{
                parent: "{parent}",
              }},
            }}
            "#,
            parent = file_url(&parent_path)
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .expect("features enabled across all edges should compile");

    assert_eq!(output.scenario.components_iter().count(), 3);
}
