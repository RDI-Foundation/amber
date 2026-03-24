#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pack from "libnpmpack";
import libnpmpublish from "libnpmpublish";
import npmFetch from "npm-registry-fetch";

import config from "./config.mjs";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const WORKSPACE_ROOT = path.resolve(SCRIPT_DIR, "..");
const PACKAGE_FILES_DIR = path.join(SCRIPT_DIR, "package-files");
const NPM_REGISTRY = "https://registry.npmjs.org/";
const { publish: publishPackage } = libnpmpublish;

function fail(message) {
  throw new Error(message);
}

function parseFlagArgs(argv) {
  const args = new Map();

  for (let index = 0; index < argv.length; index += 2) {
    args.set(argv[index], argv[index + 1]);
  }

  return args;
}

function requireFlag(args, flag) {
  const value = args.get(flag);
  if (!value) {
    fail(`missing required argument ${flag}`);
  }
  return value;
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function writeFile(file, contents, mode = 0o644) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, contents);
  fs.chmodSync(file, mode);
}

function writeJson(file, value) {
  writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
}

function copyExecutable(source, target) {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
  fs.chmodSync(target, 0o755);
}

function copyPackageFile(sourceName, targetDir, targetName, mode = 0o644) {
  const source = path.join(PACKAGE_FILES_DIR, sourceName);
  const target = path.join(targetDir, targetName);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.copyFileSync(source, target);
  fs.chmodSync(target, mode);
}

function runCommand(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    env: options.env,
    encoding: "utf8",
    stdio: options.captureOutput ? ["ignore", "pipe", "pipe"] : "inherit",
  });

  if (result.status !== 0) {
    const detail = options.captureOutput
      ? (result.stderr || result.stdout).trim()
      : `${command} exited with status ${result.status}`;
    fail(`${command} ${args.join(" ")} failed${detail ? `:\n${detail}` : ""}`);
  }

  return result.stdout ?? "";
}

function stripLeadingV(version) {
  return version.startsWith("v") ? version.slice(1) : version;
}

function npmVersionFromDockerVersion(version) {
  const npmVersion = stripLeadingV(version.trim());
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(npmVersion)) {
    fail(`invalid npm version derived from ${version}`);
  }
  return npmVersion;
}

function wildcardCandidate(versionSpec, sequence) {
  return npmVersionFromDockerVersion(`${versionSpec.slice(0, -1)}${sequence}`);
}

function wildcardSeed(versionSpec) {
  return wildcardCandidate(versionSpec, 0);
}

function scopedPackageName(name) {
  return `${config.scope}/${name}`;
}

function packageDir(root, name) {
  return path.join(root, name);
}

function expandBinaryPackage(entry) {
  const binaryName = entry.binary_name ?? entry.name;
  const dockerImage = entry.docker_image ?? entry.name;
  const cargoPackage = entry.cargo_package ?? dockerImage;
  const dockerBinaryPath = entry.docker_binary_path ?? `/${binaryName}`;
  const platforms = [
    {
      name: "linux-x64",
      runner: "ubuntu-latest",
      source: "docker",
      binary_path: dockerBinaryPath,
    },
    {
      name: "linux-arm64",
      runner: "ubuntu-24.04-arm",
      source: "docker",
      binary_path: dockerBinaryPath,
    },
  ];

  if (entry.publish_macos) {
    platforms.push({
      name: "darwin-arm64",
      runner: "macos-14",
      source: "cargo",
      cargo_package: cargoPackage,
      target: "aarch64-apple-darwin",
    });
  }

  return {
    name: entry.name,
    package_name: scopedPackageName(entry.name),
    description: entry.description ?? `Amber ${binaryName} binary`,
    docker_image: dockerImage,
    cargo_package: cargoPackage,
    binary_name: binaryName,
    platforms,
  };
}

function expandBundlePackage(entry, binariesByName) {
  const dependencies = entry.dependencies.map((name) => {
    const binaryPackage = binariesByName.get(name);
    if (!binaryPackage) {
      fail(`unknown bundle dependency ${name}`);
    }

    return {
      name: binaryPackage.name,
      package_name: binaryPackage.package_name,
      binary_name: binaryPackage.binary_name,
    };
  });

  return {
    name: entry.name,
    package_name: scopedPackageName(entry.name),
    description: entry.description ?? `Amber ${entry.name} bundle`,
    version_spec: entry.version,
    entry_binary: entry.binary_name ?? entry.name,
    dependencies,
  };
}

function expandedSpec() {
  const binaryPackages = config.binaries.map(expandBinaryPackage);
  const binariesByName = new Map(binaryPackages.map((entry) => [entry.name, entry]));
  const bundlePackages = config.bundles.map((entry) => expandBundlePackage(entry, binariesByName));

  return {
    scope: config.scope,
    binary_packages: binaryPackages,
    bundle_packages: bundlePackages,
  };
}

function readSpec(args) {
  const specPath = args.get("--spec");
  return specPath ? readJson(specPath) : expandedSpec();
}

function matrixFromSpec(spec) {
  return {
    include: spec.binary_packages.flatMap((binaryPackage) =>
      binaryPackage.platforms.map((platform) => ({
        package_dir: binaryPackage.name,
        docker_image: binaryPackage.docker_image,
        binary_name: binaryPackage.binary_name,
        platform: platform.name,
        runner: platform.runner,
        source: platform.source,
        binary_path: platform.binary_path ?? "",
        cargo_package: platform.cargo_package ?? "",
        target: platform.target ?? "",
      })),
    ),
  };
}

function commonPackageJson({ fullName, version, description }) {
  return {
    name: fullName,
    version,
    description,
    license: "Apache-2.0",
    repository: {
      type: "git",
      url: "git+https://github.com/RDI-Foundation/amber.git",
    },
    homepage: "https://github.com/RDI-Foundation/amber#readme",
    bugs: {
      url: "https://github.com/RDI-Foundation/amber/issues",
    },
    engines: {
      node: ">=18",
    },
  };
}

function stageBinaryPackage({ artifactRoot, outDir, binaryPackage, version }) {
  const targetDir = packageDir(outDir, binaryPackage.name);
  const artifacts = {};

  for (const platform of binaryPackage.platforms) {
    const source = path.join(
      artifactRoot,
      binaryPackage.name,
      platform.name,
      binaryPackage.binary_name,
    );
    const relativeTarget = path.join("artifacts", platform.name, binaryPackage.binary_name);
    copyExecutable(source, path.join(targetDir, relativeTarget));
    artifacts[platform.name] = relativeTarget;
  }

  writeJson(path.join(targetDir, "package.json"), {
    ...commonPackageJson({
      fullName: binaryPackage.package_name,
      version,
      description: binaryPackage.description,
    }),
    bin: {
      [binaryPackage.binary_name]: "./bin/run.cjs",
    },
    files: ["LICENSE", "artifacts", "bin", "lib"],
    amber: {
      artifacts,
    },
  });
  fs.copyFileSync(path.join(WORKSPACE_ROOT, "LICENSE"), path.join(targetDir, "LICENSE"));
  copyPackageFile("platform.cjs", targetDir, "lib/platform.cjs");
  copyPackageFile("binary-run.cjs", targetDir, "bin/run.cjs", 0o755);
}

function stageBundlePackage({ outDir, bundlePackage, binaryPackageVersions }) {
  const targetDir = packageDir(outDir, bundlePackage.name);
  const runtimeDependencies = bundlePackage.dependencies.map((dependency) => ({
    ...dependency,
    version: binaryPackageVersions.get(dependency.name),
  }));

  writeJson(path.join(targetDir, "package.json"), {
    ...commonPackageJson({
      fullName: bundlePackage.package_name,
      version: wildcardSeed(bundlePackage.version_spec),
      description: bundlePackage.description,
    }),
    bin: {
      [bundlePackage.entry_binary]: "./bin/run.cjs",
    },
    files: ["LICENSE", "bin", "lib"],
    scripts: {
      postinstall: "node ./lib/install-runtime.cjs",
    },
    dependencies: Object.fromEntries(
      runtimeDependencies.map((dependency) => [dependency.package_name, dependency.version]),
    ),
    amber: {
      entry_binary: bundlePackage.entry_binary,
      runtime_dependencies: runtimeDependencies.map((dependency) => ({
        package_name: dependency.package_name,
        binary_name: dependency.binary_name,
      })),
    },
  });
  fs.copyFileSync(path.join(WORKSPACE_ROOT, "LICENSE"), path.join(targetDir, "LICENSE"));
  copyPackageFile("platform.cjs", targetDir, "lib/platform.cjs");
  copyPackageFile("bundle-install-runtime.cjs", targetDir, "lib/install-runtime.cjs", 0o755);
  copyPackageFile("bundle-run.cjs", targetDir, "bin/run.cjs", 0o755);
}

function stagePackages({ spec, dockerVersionTags, artifactRoot, outDir }) {
  const dockerVersionsByImage = new Map(
    dockerVersionTags.images.map((entry) => [entry.name, npmVersionFromDockerVersion(entry.version)]),
  );
  const binaryPackageVersions = new Map();

  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });

  for (const binaryPackage of spec.binary_packages) {
    const version = dockerVersionsByImage.get(binaryPackage.docker_image);
    if (!version) {
      fail(`missing resolved docker version for ${binaryPackage.docker_image}`);
    }

    stageBinaryPackage({
      artifactRoot,
      outDir,
      binaryPackage,
      version,
    });
    binaryPackageVersions.set(binaryPackage.name, version);
  }

  for (const bundlePackage of spec.bundle_packages) {
    stageBundlePackage({
      outDir,
      bundlePackage,
      binaryPackageVersions,
    });
  }
}

function readPackageJson(dir) {
  return readJson(path.join(dir, "package.json"));
}

function writePackageJson(dir, packageJson) {
  writeJson(path.join(dir, "package.json"), packageJson);
}

function npmAuthToken() {
  return process.env.NODE_AUTH_TOKEN || process.env.NPM_TOKEN || null;
}

function npmRegistryOptions() {
  const token = npmAuthToken();
  if (token) {
    return {
      registry: NPM_REGISTRY,
      token,
    };
  }

  return {
    registry: NPM_REGISTRY,
  };
}

async function npmPack(dir) {
  return pack(dir, {
    dryRun: true,
    ignoreScripts: true,
  });
}

async function npmViewIntegrity(packageName, version) {
  try {
    const packument = await npmFetch.json(encodeURIComponent(packageName), npmRegistryOptions());
    return packument.versions?.[version]?.dist?.integrity ?? null;
  } catch (error) {
    if (error.code === "E404") {
      return null;
    }
    throw error;
  }
}

async function resolveBundleVersions({ spec, packageRoot }) {
  for (const bundlePackage of spec.bundle_packages) {
    const dir = packageDir(packageRoot, bundlePackage.name);
    const original = readPackageJson(dir);
    let resolved = false;

    for (let sequence = 0; sequence < 10_000; sequence += 1) {
      const version = wildcardCandidate(bundlePackage.version_spec, sequence);
      writePackageJson(dir, { ...original, version });

      const tarball = await npmPack(dir);
      const publishedIntegrity = await npmViewIntegrity(bundlePackage.package_name, version);

      if (publishedIntegrity === null || publishedIntegrity === tarball.integrity) {
        resolved = true;
        break;
      }
    }

    if (!resolved) {
      fail(`ran out of bundle versions for ${bundlePackage.package_name}`);
    }
  }
}

async function npmPublish(packageJson, tarball) {
  const token = npmAuthToken();
  if (!token) {
    fail("NODE_AUTH_TOKEN or NPM_TOKEN is required to publish npm packages");
  }

  await publishPackage(packageJson, tarball, {
    ...npmRegistryOptions(),
    access: "public",
    npmVersion: "amber-npm-tools",
  });
}

async function publishPackages({ spec, packageRoot }) {
  const packageDirs = [
    ...spec.binary_packages.map((entry) => packageDir(packageRoot, entry.name)),
    ...spec.bundle_packages.map((entry) => packageDir(packageRoot, entry.name)),
  ];

  for (const dir of packageDirs) {
    const packageJson = readPackageJson(dir);
    const tarball = await npmPack(dir);
    const publishedIntegrity = await npmViewIntegrity(packageJson.name, packageJson.version);

    if (publishedIntegrity === tarball.integrity) {
      console.log(`skip ${packageJson.name}@${packageJson.version}: already published`);
      continue;
    }

    if (publishedIntegrity !== null) {
      fail(`${packageJson.name}@${packageJson.version} already exists with different contents`);
    }

    await npmPublish(packageJson, tarball);
  }
}

function dockerRegistry() {
  return readJson(path.join(WORKSPACE_ROOT, "docker", "images.json")).registry.replace(/\/+$/, "");
}

function buildArtifact(args) {
  const packageDirName = requireFlag(args, "--package-dir");
  const platform = requireFlag(args, "--platform");
  const source = requireFlag(args, "--source");
  const binaryName = requireFlag(args, "--binary-name");
  const outDir = requireFlag(args, "--out-dir");
  const targetDir = path.join(outDir, packageDirName, platform);
  const targetPath = path.join(targetDir, binaryName);

  fs.mkdirSync(targetDir, { recursive: true });

  if (source === "docker") {
    const dockerImage = requireFlag(args, "--docker-image");
    const binaryPath = requireFlag(args, "--binary-path");
    const sha = requireFlag(args, "--sha");
    const ref = `${dockerRegistry()}/${dockerImage}:${sha}`;

    runCommand("docker", ["pull", ref]);
    const containerId = runCommand("docker", ["create", ref], { captureOutput: true }).trim();

    try {
      runCommand("docker", ["cp", `${containerId}:${binaryPath}`, targetPath]);
      fs.chmodSync(targetPath, 0o755);
    } finally {
      runCommand("docker", ["rm", "-f", containerId], { captureOutput: true });
    }

    return;
  }

  if (source === "cargo") {
    const cargoPackage = requireFlag(args, "--cargo-package");
    const target = requireFlag(args, "--target");

    runCommand("cargo", ["build", "-p", cargoPackage, "--release", "--target", target], {
      cwd: WORKSPACE_ROOT,
      env: process.env,
    });
    copyExecutable(path.join(WORKSPACE_ROOT, "target", target, "release", binaryName), targetPath);
    return;
  }

  fail(`unsupported artifact source ${source}`);
}

function resolvedDockerVersionTags(sha) {
  return JSON.parse(
    runCommand(
      "cargo",
      [
        "run",
        "-q",
        "-p",
        "amber-images",
        "--bin",
        "version_tags",
        "--",
        "--resolve",
        "--registry",
        dockerRegistry(),
        "--sha",
        sha,
        "docker/images.json",
      ],
      {
        cwd: WORKSPACE_ROOT,
        env: process.env,
        captureOutput: true,
      },
    ),
  );
}

function stageCommand(args) {
  stagePackages({
    spec: readSpec(args),
    dockerVersionTags: readJson(requireFlag(args, "--docker-version-tags")),
    artifactRoot: requireFlag(args, "--artifact-root"),
    outDir: requireFlag(args, "--out-dir"),
  });
}

async function publishRelease(args) {
  const spec = readSpec(args);
  const outDir = requireFlag(args, "--out-dir");

  stagePackages({
    spec,
    dockerVersionTags: resolvedDockerVersionTags(requireFlag(args, "--sha")),
    artifactRoot: requireFlag(args, "--artifact-root"),
    outDir,
  });
  await resolveBundleVersions({
    spec,
    packageRoot: outDir,
  });
  await publishPackages({
    spec,
    packageRoot: outDir,
  });
}

const [command, ...argv] = process.argv.slice(2);
const args = parseFlagArgs(argv);

async function main() {
  switch (command) {
    case "spec":
      console.log(JSON.stringify(expandedSpec(), null, 2));
      break;
    case "matrix":
      console.log(JSON.stringify(matrixFromSpec(readSpec(args))));
      break;
    case "artifact":
      buildArtifact(args);
      break;
    case "stage":
      stageCommand(args);
      break;
    case "publish-release":
      await publishRelease(args);
      break;
    default:
      fail("usage: release.mjs <spec|matrix|artifact|stage|publish-release> [command arguments]");
  }
}

await main();
