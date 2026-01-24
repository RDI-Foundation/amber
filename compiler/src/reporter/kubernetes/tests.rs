use super::*;

#[test]
fn test_sanitize_dns_name() {
    assert_eq!(sanitize_dns_name("hello"), "hello");
    assert_eq!(sanitize_dns_name("Hello-World"), "hello-world");
    assert_eq!(sanitize_dns_name("hello_world"), "hello-world");
    assert_eq!(sanitize_dns_name("hello--world"), "hello-world");
    assert_eq!(sanitize_dns_name("-hello-"), "hello");
    assert_eq!(sanitize_dns_name("UPPERCASE"), "uppercase");
    assert_eq!(sanitize_dns_name("with spaces"), "with-spaces");
    assert_eq!(sanitize_dns_name(""), "component");
    assert_eq!(sanitize_dns_name("---"), "component");
}

#[test]
fn test_truncate_dns_name() {
    assert_eq!(truncate_dns_name("short", 63), "short");
    let long = "a".repeat(100);
    assert_eq!(truncate_dns_name(&long, 63).len(), 63);
    assert_eq!(truncate_dns_name("hello-", 5), "hello");
}

#[test]
fn test_sanitize_label_value() {
    assert_eq!(sanitize_label_value("hello"), "hello");
    assert_eq!(sanitize_label_value("hello-world"), "hello-world");
    assert_eq!(sanitize_label_value("hello_world"), "hello_world");
    assert_eq!(sanitize_label_value("hello.world"), "hello.world");
    assert_eq!(sanitize_label_value("hello@world"), "helloworld");
}

#[test]
fn test_sanitize_port_name() {
    assert_eq!(sanitize_port_name("http"), "http");
    assert_eq!(sanitize_port_name("HTTP"), "http");
    // Truncated to 15 chars, trailing hyphen stripped
    assert_eq!(sanitize_port_name("very-long-port-name"), "very-long-port");
}

#[test]
fn test_service_name() {
    assert_eq!(service_name(ComponentId(0), "server"), "c0-server");
    assert_eq!(service_name(ComponentId(1), "My Service"), "c1-my-service");
    assert_eq!(service_name(ComponentId(42), "test"), "c42-test");
}

#[test]
fn test_schema_leaf_secret_field() {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {
            "api_key": {
                "type": "string",
                "secret": true
            },
            "log_level": {
                "type": "string"
            },
            "database": {
                "type": "object",
                "properties": {
                    "password": {
                        "type": "string",
                        "secret": true
                    },
                    "host": {
                        "type": "string"
                    }
                }
            }
        }
    });

    let leaves = rc::collect_leaf_paths(&schema).expect("collect leaf paths");
    let secrets: std::collections::HashSet<_> = leaves
        .iter()
        .filter(|l| l.secret)
        .map(|l| l.path.as_str())
        .collect();
    let non_secrets: std::collections::HashSet<_> = leaves
        .iter()
        .filter(|l| !l.secret)
        .map(|l| l.path.as_str())
        .collect();

    assert!(secrets.contains("api_key"));
    assert!(secrets.contains("database.password"));
    assert!(non_secrets.contains("log_level"));
    assert!(non_secrets.contains("database.host"));
}

#[test]
fn test_collect_config_refs() {
    use amber_template::TemplatePart;
    use std::collections::BTreeMap;

    // Test with Root template - should return None (all config needed)
    let root_template = rc::RootConfigTemplate::Root;
    assert_eq!(collect_config_refs(&root_template), None);

    // Test with Node template containing config refs
    let mut map = BTreeMap::new();
    map.insert(
        "token".to_string(),
        rc::ConfigNode::ConfigRef("api.token".to_string()),
    );
    map.insert(
        "url".to_string(),
        rc::ConfigNode::StringTemplate(vec![
            TemplatePart::lit("http://"),
            TemplatePart::config("api.host".to_string()),
            TemplatePart::lit(":8080"),
        ]),
    );
    map.insert("port".to_string(), rc::ConfigNode::Number(8080.into()));

    let node_template = rc::RootConfigTemplate::Node(rc::ConfigNode::Object(map));
    let paths = collect_config_refs(&node_template).expect("should have paths");

    assert_eq!(paths.len(), 2);
    assert!(paths.contains("api.token"));
    assert!(paths.contains("api.host"));

    // Test with nested structure
    let mut inner_map = BTreeMap::new();
    inner_map.insert(
        "secret".to_string(),
        rc::ConfigNode::ConfigRef("db.password".to_string()),
    );

    let mut outer_map = BTreeMap::new();
    outer_map.insert("database".to_string(), rc::ConfigNode::Object(inner_map));
    outer_map.insert("static".to_string(), rc::ConfigNode::String("value".to_string()));

    let nested_template = rc::RootConfigTemplate::Node(rc::ConfigNode::Object(outer_map));
    let paths = collect_config_refs(&nested_template).expect("should have paths");

    assert_eq!(paths.len(), 1);
    assert!(paths.contains("db.password"));

    // Test with array containing config refs
    let array_node = rc::ConfigNode::Array(vec![
        rc::ConfigNode::ConfigRef("item1".to_string()),
        rc::ConfigNode::String("literal".to_string()),
        rc::ConfigNode::ConfigRef("item2".to_string()),
    ]);

    let array_template = rc::RootConfigTemplate::Node(array_node);
    let paths = collect_config_refs(&array_template).expect("should have paths");

    assert_eq!(paths.len(), 2);
    assert!(paths.contains("item1"));
    assert!(paths.contains("item2"));
}
