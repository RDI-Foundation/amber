use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use amber_config as rc;
use serde_json::Value;

#[derive(Debug)]
pub(crate) struct ConfigScopeError {
    message: String,
}

impl ConfigScopeError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ConfigScopeError {}

impl From<String> for ConfigScopeError {
    fn from(message: String) -> Self {
        Self::new(message)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeConfigView {
    pub(crate) allowed_root_leaf_paths: BTreeSet<String>,
    pub(crate) pruned_root_schema: Value,
    pub(crate) component_template: rc::RootConfigTemplate,
    pub(crate) component_schema: Value,
}

pub(crate) fn build_runtime_config_view(
    component_label: &str,
    root_schema: &Value,
    root_leaves: &[rc::SchemaLeaf],
    component_template: &rc::RootConfigTemplate,
    component_schema: &Value,
    used_component_paths: &BTreeSet<String>,
) -> Result<RuntimeConfigView, ConfigScopeError> {
    if used_component_paths.is_empty() {
        return Err(ConfigScopeError::new(format!(
            "internal error: no runtime config paths for {component_label}"
        )));
    }

    let component_leaves = rc::collect_leaf_paths(component_schema).map_err(|e| {
        ConfigScopeError::new(format!(
            "failed to enumerate component config definition leaf paths for {component_label}: {e}"
        ))
    })?;
    let allowed_component_leaf_paths =
        allowed_leaf_paths_for_used_paths(&component_leaves, used_component_paths);
    if allowed_component_leaf_paths.is_empty() {
        return Err(ConfigScopeError::new(format!(
            "internal error: no component config leaves selected for {component_label}"
        )));
    }

    let pruned_component_schema = prune_component_schema(
        component_label,
        component_schema,
        &allowed_component_leaf_paths,
    )?;
    let pruned_component_template = prune_component_template(
        component_label,
        component_template,
        used_component_paths,
        &allowed_component_leaf_paths,
    )?;

    // Security: only expose root config leaves needed to resolve the used component config paths.
    let allowed_root_leaf_paths = allowed_root_leaf_paths(root_leaves, &pruned_component_template);
    let pruned_root_schema =
        prune_root_schema(component_label, root_schema, &allowed_root_leaf_paths)?;

    Ok(RuntimeConfigView {
        allowed_root_leaf_paths,
        pruned_root_schema,
        component_template: pruned_component_template,
        component_schema: pruned_component_schema,
    })
}

fn collect_config_refs(template: &rc::RootConfigTemplate) -> Option<BTreeSet<String>> {
    fn collect_from_node(node: &rc::ConfigNode, acc: &mut BTreeSet<String>) {
        match node {
            rc::ConfigNode::ConfigRef(path) => {
                acc.insert(path.clone());
            }
            rc::ConfigNode::StringTemplate(parts) => {
                for part in parts {
                    if let amber_template::TemplatePart::Config { config } = part {
                        acc.insert(config.clone());
                    }
                }
            }
            rc::ConfigNode::Array(items) => {
                for item in items {
                    collect_from_node(item, acc);
                }
            }
            rc::ConfigNode::Object(map) => {
                for value in map.values() {
                    collect_from_node(value, acc);
                }
            }
            _ => {}
        }
    }

    match template {
        rc::RootConfigTemplate::Root => None,
        rc::RootConfigTemplate::Node(node) => {
            let mut paths = BTreeSet::new();
            collect_from_node(node, &mut paths);
            Some(paths)
        }
    }
}

fn allowed_root_leaf_paths(
    root_leaves: &[rc::SchemaLeaf],
    component_template: &rc::RootConfigTemplate,
) -> BTreeSet<String> {
    if matches!(component_template, rc::RootConfigTemplate::Root) {
        return root_leaves.iter().map(|leaf| leaf.path.clone()).collect();
    }

    let Some(paths) = collect_config_refs(component_template) else {
        return BTreeSet::new();
    };

    let mut allowed = BTreeSet::new();
    for path in paths {
        if path.is_empty() {
            return root_leaves.iter().map(|leaf| leaf.path.clone()).collect();
        }
        for leaf in root_leaves {
            if leaf.path == path {
                allowed.insert(leaf.path.clone());
                continue;
            }
            if leaf.path.starts_with(&path) && leaf.path.as_bytes().get(path.len()) == Some(&b'.') {
                allowed.insert(leaf.path.clone());
            }
        }
    }

    allowed
}

fn allowed_leaf_paths_for_used_paths(
    leaves: &[rc::SchemaLeaf],
    used_paths: &BTreeSet<String>,
) -> BTreeSet<String> {
    if used_paths.contains("") {
        return leaves.iter().map(|leaf| leaf.path.clone()).collect();
    }

    let mut allowed = BTreeSet::new();
    for path in used_paths {
        if path.is_empty() {
            return leaves.iter().map(|leaf| leaf.path.clone()).collect();
        }
        for leaf in leaves {
            if leaf.path == *path {
                allowed.insert(leaf.path.clone());
                continue;
            }
            if leaf.path.starts_with(path) && leaf.path.as_bytes().get(path.len()) == Some(&b'.') {
                allowed.insert(leaf.path.clone());
            }
        }
    }

    allowed
}

fn prune_root_schema(
    component_label: &str,
    root_schema: &Value,
    allowed_leaf_paths: &BTreeSet<String>,
) -> Result<Value, ConfigScopeError> {
    rc::prune_schema(root_schema, allowed_leaf_paths).map_err(|err| {
        ConfigScopeError::new(format!(
            "failed to prune root config schema for {component_label}: {err}"
        ))
    })
}

fn prune_component_schema(
    component_label: &str,
    component_schema: &Value,
    allowed_leaf_paths: &BTreeSet<String>,
) -> Result<Value, ConfigScopeError> {
    rc::prune_schema(component_schema, allowed_leaf_paths).map_err(|err| {
        ConfigScopeError::new(format!(
            "failed to prune component config schema for {component_label}: {err}"
        ))
    })
}

fn prune_component_template(
    component_label: &str,
    component_template: &rc::RootConfigTemplate,
    used_paths: &BTreeSet<String>,
    allowed_leaf_paths: &BTreeSet<String>,
) -> Result<rc::RootConfigTemplate, ConfigScopeError> {
    if used_paths.contains("") {
        return Ok(component_template.clone());
    }

    let node = match component_template {
        rc::RootConfigTemplate::Root => rc::ConfigNode::ConfigRef(String::new()),
        rc::RootConfigTemplate::Node(node) => node.clone(),
    };

    let pruned = prune_config_node(&node, "", used_paths, allowed_leaf_paths).map_err(|err| {
        ConfigScopeError::new(format!(
            "failed to prune component config template for {component_label}: {err}"
        ))
    })?;

    let Some(pruned) = pruned else {
        return Err(ConfigScopeError::new(format!(
            "failed to prune component config template for {component_label}: no matching config \
             paths"
        )));
    };

    Ok(rc::RootConfigTemplate::Node(pruned))
}

fn prune_config_node(
    node: &rc::ConfigNode,
    path: &str,
    used_paths: &BTreeSet<String>,
    allowed_leaf_paths: &BTreeSet<String>,
) -> Result<Option<rc::ConfigNode>, String> {
    if used_paths.contains(path) {
        match node {
            rc::ConfigNode::ConfigRef(root_path) => {
                return Ok(Some(project_config_ref(
                    root_path,
                    path,
                    allowed_leaf_paths,
                )?));
            }
            rc::ConfigNode::Object(_) => {}
            _ => return Ok(Some(node.clone())),
        }
    }

    if !path_or_descendant_allowed(path, allowed_leaf_paths) {
        return Ok(None);
    }

    match node {
        rc::ConfigNode::Object(map) => {
            let mut out = BTreeMap::new();
            for (k, v) in map {
                let child_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if !path_or_descendant_allowed(&child_path, allowed_leaf_paths) {
                    continue;
                }
                if let Some(child) =
                    prune_config_node(v, &child_path, used_paths, allowed_leaf_paths)?
                {
                    out.insert(k.clone(), child);
                }
            }
            if out.is_empty() {
                Ok(None)
            } else {
                Ok(Some(rc::ConfigNode::Object(out)))
            }
        }
        rc::ConfigNode::ConfigRef(root_path) => Ok(Some(project_config_ref(
            root_path,
            path,
            allowed_leaf_paths,
        )?)),
        other => Ok(Some(other.clone())),
    }
}

fn project_config_ref(
    root_path: &str,
    prefix: &str,
    allowed_leaf_paths: &BTreeSet<String>,
) -> Result<rc::ConfigNode, String> {
    if allowed_leaf_paths.contains(prefix) {
        return Ok(rc::ConfigNode::ConfigRef(root_path.to_string()));
    }

    let prefix_with_dot = if prefix.is_empty() {
        String::new()
    } else {
        format!("{prefix}.")
    };

    let mut out = BTreeMap::new();
    for leaf in allowed_leaf_paths {
        let suffix = match leaf.strip_prefix(&prefix_with_dot) {
            Some(suffix) => suffix,
            None => continue,
        };
        if suffix.is_empty() {
            continue;
        }
        let ref_path = if root_path.is_empty() {
            suffix.to_string()
        } else {
            format!("{root_path}.{suffix}")
        };
        insert_config_node(&mut out, suffix, rc::ConfigNode::ConfigRef(ref_path))?;
    }

    if out.is_empty() {
        return Err("no leaf paths selected under config ref".to_string());
    }

    Ok(rc::ConfigNode::Object(out))
}

fn insert_config_node(
    map: &mut BTreeMap<String, rc::ConfigNode>,
    path: &str,
    node: rc::ConfigNode,
) -> Result<(), String> {
    let segments: Vec<&str> = path.split('.').collect();
    insert_config_node_segments(map, &segments, node)
}

fn insert_config_node_segments(
    map: &mut BTreeMap<String, rc::ConfigNode>,
    segments: &[&str],
    node: rc::ConfigNode,
) -> Result<(), String> {
    let Some((first, rest)) = segments.split_first() else {
        return Err("cannot insert config node at empty path".to_string());
    };

    if rest.is_empty() {
        map.insert((*first).to_string(), node);
        return Ok(());
    }

    let entry = map
        .entry((*first).to_string())
        .or_insert_with(|| rc::ConfigNode::Object(BTreeMap::new()));
    let rc::ConfigNode::Object(child) = entry else {
        return Err(format!(
            "config template path {:?} conflicts with non-object node",
            segments.join(".")
        ));
    };

    insert_config_node_segments(child, rest, node)
}

fn path_or_descendant_allowed(path: &str, allowed_leaf_paths: &BTreeSet<String>) -> bool {
    if path.is_empty() {
        return !allowed_leaf_paths.is_empty();
    }
    for allowed in allowed_leaf_paths {
        if allowed == path {
            return true;
        }
        if allowed.starts_with(path) && allowed.as_bytes().get(path.len()) == Some(&b'.') {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use amber_template::TemplatePart;
    use serde_json::json;

    use super::*;

    #[test]
    fn build_runtime_config_view_prunes_unneeded_paths() {
        let root_schema = json!({
            "type": "object",
            "properties": {
                "app": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "log_level": { "type": "string" }
                    }
                },
                "token": { "type": "string", "secret": true }
            }
        });
        let root_leaves = rc::collect_leaf_paths(&root_schema).expect("collect root leaves");

        let component_schema = json!({
            "type": "object",
            "properties": {
                "app": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "log_level": { "type": "string" }
                    }
                },
                "token": { "type": "string" }
            }
        });
        let component_template =
            rc::RootConfigTemplate::Node(rc::ConfigNode::Object(BTreeMap::from([
                (
                    "app".to_string(),
                    rc::ConfigNode::ConfigRef("app".to_string()),
                ),
                (
                    "token".to_string(),
                    rc::ConfigNode::ConfigRef("token".to_string()),
                ),
            ])));
        let used_component_paths = BTreeSet::from(["app.name".to_string()]);

        let view = build_runtime_config_view(
            "/child",
            &root_schema,
            &root_leaves,
            &component_template,
            &component_schema,
            &used_component_paths,
        )
        .expect("build view");

        assert_eq!(
            view.allowed_root_leaf_paths,
            BTreeSet::from(["app.name".to_string()])
        );
        assert!(
            view.pruned_root_schema["properties"]["app"]["properties"]
                .get("name")
                .is_some()
        );
        assert!(
            view.pruned_root_schema["properties"]["app"]["properties"]
                .get("log_level")
                .is_none()
        );
        assert!(view.pruned_root_schema["properties"].get("token").is_none());

        assert!(
            view.component_schema["properties"]["app"]["properties"]
                .get("name")
                .is_some()
        );
        assert!(
            view.component_schema["properties"]["app"]["properties"]
                .get("log_level")
                .is_none()
        );
        assert!(view.component_schema["properties"].get("token").is_none());

        let template_json = view.component_template.to_json_ir().to_string();
        assert!(template_json.contains("app.name"));
        assert!(!template_json.contains("log_level"));
        assert!(!template_json.contains("token"));
    }

    #[test]
    fn build_runtime_config_view_keeps_full_scope_for_full_object_access() {
        let root_schema = json!({
            "type": "object",
            "properties": {
                "app": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "log_level": { "type": "string" }
                    }
                },
                "token": { "type": "string", "secret": true }
            }
        });
        let root_leaves = rc::collect_leaf_paths(&root_schema).expect("collect root leaves");
        let expected_root_leaves: BTreeSet<String> =
            root_leaves.iter().map(|leaf| leaf.path.clone()).collect();

        let component_schema = json!({
            "type": "object",
            "properties": {
                "app": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "log_level": { "type": "string" }
                    }
                },
                "token": { "type": "string" }
            }
        });
        let component_template = rc::RootConfigTemplate::Root;
        let used_component_paths = BTreeSet::from(["".to_string()]);

        let view = build_runtime_config_view(
            "/child",
            &root_schema,
            &root_leaves,
            &component_template,
            &component_schema,
            &used_component_paths,
        )
        .expect("build view");

        assert_eq!(view.allowed_root_leaf_paths, expected_root_leaves);
        assert!(
            view.pruned_root_schema["properties"]["app"]["properties"]
                .get("name")
                .is_some()
        );
        assert!(
            view.pruned_root_schema["properties"]["app"]["properties"]
                .get("log_level")
                .is_some()
        );
        assert!(view.pruned_root_schema["properties"].get("token").is_some());

        assert!(
            view.component_schema["properties"]["app"]["properties"]
                .get("name")
                .is_some()
        );
        assert!(
            view.component_schema["properties"]["app"]["properties"]
                .get("log_level")
                .is_some()
        );
        assert!(view.component_schema["properties"].get("token").is_some());
        assert!(matches!(
            view.component_template,
            rc::RootConfigTemplate::Root
        ));
    }

    #[test]
    fn build_runtime_config_view_rejects_unknown_component_paths() {
        let root_schema = json!({
            "type": "object",
            "properties": {
                "app": { "type": "string" }
            }
        });
        let root_leaves = rc::collect_leaf_paths(&root_schema).expect("collect root leaves");

        let component_schema = json!({
            "type": "object",
            "properties": {
                "app": { "type": "string" }
            }
        });
        let component_template =
            rc::RootConfigTemplate::Node(rc::ConfigNode::Object(BTreeMap::from([(
                "app".to_string(),
                rc::ConfigNode::ConfigRef("app".to_string()),
            )])));
        let used_component_paths = BTreeSet::from(["missing.path".to_string()]);

        let err = build_runtime_config_view(
            "/child",
            &root_schema,
            &root_leaves,
            &component_template,
            &component_schema,
            &used_component_paths,
        )
        .expect_err("missing component path should fail");

        assert!(
            err.to_string()
                .contains("no component config leaves selected"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_runtime_config_view_scopes_string_template_refs() {
        let root_schema = json!({
            "type": "object",
            "properties": {
                "repo": { "type": "string" },
                "tag": { "type": "string" },
                "token": { "type": "string", "secret": true }
            }
        });
        let root_leaves = rc::collect_leaf_paths(&root_schema).expect("collect root leaves");

        let component_schema = json!({
            "type": "object",
            "properties": {
                "image": { "type": "string" },
                "token": { "type": "string" }
            }
        });
        let component_template =
            rc::RootConfigTemplate::Node(rc::ConfigNode::Object(BTreeMap::from([
                (
                    "image".to_string(),
                    rc::ConfigNode::StringTemplate(vec![
                        TemplatePart::config("repo"),
                        TemplatePart::lit(":"),
                        TemplatePart::config("tag"),
                    ]),
                ),
                (
                    "token".to_string(),
                    rc::ConfigNode::ConfigRef("token".to_string()),
                ),
            ])));
        let used_component_paths = BTreeSet::from(["image".to_string()]);

        let view = build_runtime_config_view(
            "/child",
            &root_schema,
            &root_leaves,
            &component_template,
            &component_schema,
            &used_component_paths,
        )
        .expect("build view");

        assert_eq!(
            view.allowed_root_leaf_paths,
            BTreeSet::from(["repo".to_string(), "tag".to_string()])
        );
        assert!(view.pruned_root_schema["properties"].get("repo").is_some());
        assert!(view.pruned_root_schema["properties"].get("tag").is_some());
        assert!(view.pruned_root_schema["properties"].get("token").is_none());

        assert!(view.component_schema["properties"].get("image").is_some());
        assert!(view.component_schema["properties"].get("token").is_none());

        let template_json = view.component_template.to_json_ir().to_string();
        assert!(template_json.contains("repo"));
        assert!(template_json.contains("tag"));
        assert!(!template_json.contains("token"));
    }
}
