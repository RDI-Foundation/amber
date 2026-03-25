// Edit this file, then inspect the expanded output with:
//   node npm/release.mjs spec
//
// Defaults applied by the release script:
// - npm package name defaults to `${scope}/${name}`
// - Docker image defaults to `name`
// - Cargo package defaults to the Docker image name
// - binary name defaults to `name`
// - Linux x64 and arm64 artifacts are produced from the published Docker images
// - Docker-side binary path defaults to `/${binary_name}`
// - macOS arm64 artifacts are only produced when `publish_macos: true`
// - runtime packages publish one top-level npm package plus one platform package per
//   supported OS/arch combination

export default {
  scope: "@rdif",

  binaries: [
    {
      name: "amber-cli",
      description: "Amber CLI compiler binary",
      binary_name: "amber",
      docker_image: "amber-cli",
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
  ],

  runtime_packages: [
    {
      name: "amber",
      description: "Amber CLI plus the local runtime binaries required by amber run",
      version: "v0.3.x",
      entry_binary_package: "amber-cli",
      runtime_binaries: ["amber-cli", "amber-router", "amber-helper"],
    },
  ],
};
