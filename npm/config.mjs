// Edit this file, then inspect the expanded output with:
//   node npm/release.mjs spec
//
// Defaults applied by the release script:
// - npm package name defaults to `${scope}/${name}`
// - Docker image defaults to `name`
// - Cargo package defaults to the Docker image name
// - binary name defaults to `name`
// - Linux x64 and arm64 packages are produced from the published Docker images
// - Docker-side binary path defaults to `/${binary_name}`
// - macOS arm64 packages are only produced when `publish_macos: true`

export default {
  scope: "@rdif",

  binaries: [
    {
      name: "amber-cli",
      description: "Amber CLI compiler binary",
      binary_name: "amber",
      docker_image: "amber-cli",
      publish: false,
      publish_macos: true,
    },
    {
      name: "amber-helper",
      description: "Amber helper runtime binary",
      docker_image: "amber-helper",
      publish_macos: true,
    },
    {
      name: "amber-router",
      description: "Amber router runtime binary",
      docker_image: "amber-router",
      publish_macos: true,
    },
    {
      name: "amber-provisioner",
      description: "Amber provisioner runtime binary",
      docker_image: "amber-provisioner",
    },
    {
      name: "amber-docker-gateway",
      description: "Amber Docker gateway runtime binary",
      docker_image: "amber-docker-gateway",
    },
    {
      name: "amber-manager",
      description: "Amber scenario manager binary",
      docker_image: "amber-manager",
      docker_binary_path: "/usr/local/bin/amber-manager",
    },
  ],

  bundles: [
    {
      name: "amber",
      description: "Amber CLI plus the local runtime binaries required by amber run",
      version: "v0.3.x",
      binary_name: "amber",
      entry_package: "amber-cli",
      dependencies: ["amber-router", "amber-helper"],
    },
  ],
};
