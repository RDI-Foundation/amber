use amber_images::{
    AMBER_DOCKER_GATEWAY, AMBER_HELPER, AMBER_PROVISIONER, AMBER_ROUTER, AMBER_SITE_CONTROLLER,
    INTERNAL_IMAGE_OVERRIDE_KEYS, ImageRef, override_reference, parse_dev_image_tag_overrides,
};

#[derive(Clone, Debug)]
pub(crate) struct InternalImages {
    pub(crate) helper: String,
    pub(crate) provisioner: String,
    pub(crate) router: String,
    pub(crate) docker_gateway: String,
    pub(crate) site_controller: String,
}

pub(crate) fn resolve_internal_images() -> Result<InternalImages, String> {
    let mut images = InternalImages {
        helper: default_reference(&AMBER_HELPER),
        provisioner: default_reference(&AMBER_PROVISIONER),
        router: default_reference(&AMBER_ROUTER),
        docker_gateway: default_reference(&AMBER_DOCKER_GATEWAY),
        site_controller: default_reference(&AMBER_SITE_CONTROLLER),
    };

    for (key, value) in parse_dev_image_tag_overrides(INTERNAL_IMAGE_OVERRIDE_KEYS)? {
        match key.as_str() {
            "router" => images.router = override_reference(&AMBER_ROUTER, &value),
            "helper" => images.helper = override_reference(&AMBER_HELPER, &value),
            "provisioner" => images.provisioner = override_reference(&AMBER_PROVISIONER, &value),
            "docker_gateway" => {
                images.docker_gateway = override_reference(&AMBER_DOCKER_GATEWAY, &value)
            }
            "site_controller" => {
                images.site_controller = override_reference(&AMBER_SITE_CONTROLLER, &value)
            }
            _ => unreachable!("shared image override parser returned an unknown key"),
        }
    }

    Ok(images)
}

fn default_reference(image: &ImageRef) -> String {
    image.reference.to_string()
}
