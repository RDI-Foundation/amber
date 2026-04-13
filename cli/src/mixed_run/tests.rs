use super::*;

#[test]
fn site_state_paths_are_site_scoped() {
    let root = Path::new("/tmp/amber-run/state");
    assert_eq!(
        site_state_path(root, "site-a"),
        Path::new("/tmp/amber-run/state/site-a/manager-state.json")
    );
    assert_eq!(
        desired_links_path(Path::new("/tmp/amber-run/state/site-a")),
        Path::new("/tmp/amber-run/state/site-a/desired-links.json")
    );
    assert_eq!(
        site_controller_plan_path(Path::new("/tmp/amber-run/state/site-a")),
        Path::new("/tmp/amber-run/state/site-a/site-controller-plan.json")
    );
}

#[test]
fn site_controller_image_override_uses_dev_tag() {
    let overrides = BTreeMap::from([(
        "site_controller".to_string(),
        "dev-site-controller".to_string(),
    )]);

    assert_eq!(
        launch_bundle::site_controller_image_reference_from_overrides(&overrides),
        format!(
            "{}/{}:{}",
            amber_images::AMBER_SITE_CONTROLLER.registry,
            amber_images::AMBER_SITE_CONTROLLER.name,
            "dev-site-controller",
        )
    );
}
