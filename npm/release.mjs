#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import pack from "libnpmpack";
import npmFetch from "npm-registry-fetch";

import config from "./config.mjs";

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const WORKSPACE_ROOT = path.resolve(SCRIPT_DIR, "..");
const PACKAGE_FILES_DIR = path.join(SCRIPT_DIR, "package-files");
const NPM_REGISTRY = "https://registry.npmjs.org/";

function fail(message) {
  throw new Error(message);
}

function parseFlagArgs(argv) {
  if (argv.length % 2 !== 0) {
    fail(`expected flag/value pairs, got: ${argv.join(" ")}`);
  }

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

function npmVersionFromTag(version) {
  const npmVersion = stripLeadingV(version.trim());
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(npmVersion)) {
    fail(`invalid npm version derived from ${version}`);
  }
  return npmVersion;
}

function wildcardCandidate(versionSpec, sequence) {
  return npmVersionFromTag(`${versionSpec.slice(0, -1)}${sequence}`);
}

function wildcardSeed(versionSpec) {
  return wildcardCandidate(versionSpec, 0);
}

function wildcardPrefix(versionSpec) {
  return stripLeadingV(versionSpec.trim()).slice(0, -1);
}

function wildcardSequence(versionSpec, version) {
  const normalizedVersion = npmVersionFromTag(version);
  const prefix = wildcardPrefix(versionSpec);

  if (!normalizedVersion.startsWith(prefix)) {
    fail(`version ${version} does not match wildcard series ${versionSpec}`);
  }

  const sequence = normalizedVersion.slice(prefix.length);
  if (!/^\d+$/.test(sequence)) {
    fail(`version ${version} does not end with a numeric wildcard sequence for ${versionSpec}`);
  }

  return Number(sequence);
}

function scopedPackageName(name) {
  return `${config.scope}/${name}`;
}

function packageDir(root, name) {
  return path.join(root, name);
}

function runtimePlatformDirName(runtimePackage, platform) {
  return `${runtimePackage.name}-${platform.name}`;
}

function runtimePlatformPackageName(runtimePackage, platform) {
  return scopedPackageName(runtimePlatformDirName(runtimePackage, platform));
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
      os: "linux",
      cpu: "x64",
    },
    {
      name: "linux-arm64",
      runner: "ubuntu-24.04-arm",
      source: "docker",
      binary_path: dockerBinaryPath,
      os: "linux",
      cpu: "arm64",
    },
  ];

  if (entry.publish_macos) {
    platforms.push({
      name: "darwin-arm64",
      runner: "macos-14",
      source: "cargo",
      cargo_package: cargoPackage,
      target: "aarch64-apple-darwin",
      os: "darwin",
      cpu: "arm64",
    });
  }

  return {
    name: entry.name,
    description: entry.description ?? `Amber ${binaryName} binary`,
    docker_image: dockerImage,
    cargo_package: cargoPackage,
    binary_name: binaryName,
    platforms,
  };
}

function ensureUnique(entries, kind) {
  const seen = new Set();

  for (const entry of entries) {
    if (seen.has(entry.name)) {
      fail(`duplicate ${kind} ${entry.name}`);
    }
    seen.add(entry.name);
  }
}

function sharedPlatforms(binaryPackages) {
  if (binaryPackages.length === 0) {
    fail("runtime package must include at least one binary");
  }

  const firstPlatforms = new Map(
    binaryPackages[0].platforms.map((platform) => [
      platform.name,
      {
        name: platform.name,
        os: platform.os,
        cpu: platform.cpu,
      },
    ]),
  );

  for (const binaryPackage of binaryPackages.slice(1)) {
    const platformsByName = new Map(binaryPackage.platforms.map((platform) => [platform.name, platform]));

    for (const [platformName, sharedPlatform] of Array.from(firstPlatforms.entries())) {
      const platform = platformsByName.get(platformName);
      if (!platform) {
        firstPlatforms.delete(platformName);
        continue;
      }
      if (platform.os !== sharedPlatform.os || platform.cpu !== sharedPlatform.cpu) {
        fail(
          `binary ${binaryPackage.name} disagrees on ${platformName} metadata for runtime package`,
        );
      }
    }
  }

  return Array.from(firstPlatforms.values());
}

function expandRuntimePackage(entry, binaryPackagesByName) {
  const runtimeBinaries = entry.runtime_binaries.map((binaryName) => {
    const binaryPackage = binaryPackagesByName.get(binaryName);
    if (!binaryPackage) {
      fail(`unknown runtime binary ${binaryName}`);
    }
    return binaryPackage;
  });

  const entryBinaryPackage = binaryPackagesByName.get(entry.entry_binary_package);
  if (!entryBinaryPackage) {
    fail(`unknown entry binary package ${entry.entry_binary_package}`);
  }
  if (!runtimeBinaries.some((binaryPackage) => binaryPackage.name === entry.entry_binary_package)) {
    fail(
      `runtime package ${entry.name} entry binary package ${entry.entry_binary_package} must also be listed in runtime_binaries`,
    );
  }

  const platforms = sharedPlatforms(runtimeBinaries);
  if (platforms.length === 0) {
    fail(`runtime package ${entry.name} has no shared supported platforms`);
  }

  return {
    name: entry.name,
    package_name: scopedPackageName(entry.name),
    description: entry.description ?? `Amber ${entry.name} runtime`,
    version_spec: entry.version,
    entry_binary: entryBinaryPackage.binary_name,
    entry_binary_package: entry.entry_binary_package,
    runtime_binaries: runtimeBinaries.map((binaryPackage) => ({
      name: binaryPackage.name,
      binary_name: binaryPackage.binary_name,
    })),
    platforms,
  };
}

function expandedSpec() {
  const binaryPackages = config.binaries.map(expandBinaryPackage);
  ensureUnique(binaryPackages, "binary package");

  const binaryPackagesByName = new Map(binaryPackages.map((entry) => [entry.name, entry]));
  const runtimePackages = config.runtime_packages.map((entry) =>
    expandRuntimePackage(entry, binaryPackagesByName),
  );
  ensureUnique(runtimePackages, "runtime package");

  return {
    scope: config.scope,
    binary_packages: binaryPackages,
    runtime_packages: runtimePackages,
  };
}

function readSpec(args) {
  const specPath = args.get("--spec");
  return specPath ? readJson(specPath) : expandedSpec();
}

function requiredBinaryPackageNames(spec) {
  const required = new Set();

  for (const runtimePackage of spec.runtime_packages) {
    for (const runtimeBinary of runtimePackage.runtime_binaries) {
      required.add(runtimeBinary.name);
    }
  }

  return required;
}

function requiredBinaryPackages(spec) {
  const required = requiredBinaryPackageNames(spec);
  return spec.binary_packages.filter((entry) => required.has(entry.name));
}

function matrixFromSpec(spec) {
  return {
    include: requiredBinaryPackages(spec).flatMap((binaryPackage) =>
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

function runtimePlatformMap(runtimePackage) {
  return Object.fromEntries(
    runtimePackage.platforms.map((platform) => [platform.name, runtimePlatformPackageName(runtimePackage, platform)]),
  );
}

function stageRuntimePlatformPackage({
  artifactRoot,
  outDir,
  runtimePackage,
  binaryPackagesByName,
  platform,
  version,
}) {
  const targetDir = packageDir(outDir, runtimePlatformDirName(runtimePackage, platform));

  for (const runtimeBinary of runtimePackage.runtime_binaries) {
    const binaryPackage = binaryPackagesByName.get(runtimeBinary.name);
    if (!binaryPackage) {
      fail(`missing binary package ${runtimeBinary.name}`);
    }

    const source = path.join(
      artifactRoot,
      binaryPackage.name,
      platform.name,
      binaryPackage.binary_name,
    );

    if (binaryPackage.name === runtimePackage.entry_binary_package) {
      copyExecutable(source, path.join(targetDir, "bin", runtimePackage.entry_binary));
      continue;
    }

    copyExecutable(source, path.join(targetDir, "runtime-bin", binaryPackage.binary_name));
  }

  writeJson(path.join(targetDir, "package.json"), {
    ...commonPackageJson({
      fullName: runtimePlatformPackageName(runtimePackage, platform),
      version,
      description: `${runtimePackage.description} (${platform.name})`,
    }),
    os: [platform.os],
    cpu: [platform.cpu],
    bin: {
      [runtimePackage.entry_binary]: `./bin/${runtimePackage.entry_binary}`,
    },
    files: ["LICENSE", "bin", "runtime-bin"],
    amber: {
      runtime_bin_dir: "runtime-bin",
    },
  });
  fs.copyFileSync(path.join(WORKSPACE_ROOT, "LICENSE"), path.join(targetDir, "LICENSE"));
}

function stageRuntimeWrapperPackage({ outDir, runtimePackage, version }) {
  const targetDir = packageDir(outDir, runtimePackage.name);
  const platformPackages = runtimePlatformMap(runtimePackage);

  writeJson(path.join(targetDir, "package.json"), {
    ...commonPackageJson({
      fullName: runtimePackage.package_name,
      version,
      description: runtimePackage.description,
    }),
    bin: {
      [runtimePackage.entry_binary]: "./bin/run.cjs",
    },
    files: ["LICENSE", "bin", "lib"],
    optionalDependencies: Object.fromEntries(
      Object.values(platformPackages).map((packageName) => [packageName, version]),
    ),
    amber: {
      entry_binary: runtimePackage.entry_binary,
      platform_packages: platformPackages,
    },
  });
  fs.copyFileSync(path.join(WORKSPACE_ROOT, "LICENSE"), path.join(targetDir, "LICENSE"));
  copyPackageFile("platform.cjs", targetDir, "lib/platform.cjs");
  copyPackageFile("installed-binary.cjs", targetDir, "lib/installed-binary.cjs");
  copyPackageFile("runtime-run.cjs", targetDir, "bin/run.cjs", 0o755);
}

function stagePackages({ spec, artifactRoot, outDir }) {
  const binaryPackagesByName = new Map(spec.binary_packages.map((entry) => [entry.name, entry]));

  fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });

  for (const runtimePackage of spec.runtime_packages) {
    const version = wildcardSeed(runtimePackage.version_spec);

    for (const platform of runtimePackage.platforms) {
      stageRuntimePlatformPackage({
        artifactRoot,
        outDir,
        runtimePackage,
        binaryPackagesByName,
        platform,
        version,
      });
    }

    stageRuntimeWrapperPackage({
      outDir,
      runtimePackage,
      version,
    });
  }
}

function readPackageJson(dir) {
  return readJson(path.join(dir, "package.json"));
}

function writePackageJson(dir, packageJson) {
  writeJson(path.join(dir, "package.json"), packageJson);
}

function npmRegistryOptions() {
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
    const packument = await npmFetch.json(encodeURIComponent(packageName), {
      ...npmRegistryOptions(),
      query: { write: true },
    });
    return packument.versions?.[version]?.dist?.integrity ?? null;
  } catch (error) {
    if (error.code === "E404") {
      return null;
    }
    throw error;
  }
}

function runtimePackageVersionFloors({ spec, versionFloor }) {
  if (spec.runtime_packages.length !== 1) {
    fail("publish-release requires explicit per-runtime version floor handling for multiple runtime packages");
  }

  const [runtimePackage] = spec.runtime_packages;
  return new Map([
    [runtimePackage.name, wildcardSequence(runtimePackage.version_spec, versionFloor)],
  ]);
}

function setRuntimePackageVersion({ runtimePackage, packageRoot, version }) {
  const wrapperDir = packageDir(packageRoot, runtimePackage.name);
  const wrapperPackageJson = readPackageJson(wrapperDir);

  writePackageJson(wrapperDir, {
    ...wrapperPackageJson,
    version,
    optionalDependencies: Object.fromEntries(
      Object.keys(wrapperPackageJson.optionalDependencies).map((packageName) => [packageName, version]),
    ),
  });

  for (const platform of runtimePackage.platforms) {
    const platformDir = packageDir(packageRoot, runtimePlatformDirName(runtimePackage, platform));
    const platformPackageJson = readPackageJson(platformDir);
    writePackageJson(platformDir, {
      ...platformPackageJson,
      version,
    });
  }
}

function runtimePackagePublishDirs(runtimePackage, packageRoot) {
  return [
    ...runtimePackage.platforms.map((platform) =>
      packageDir(packageRoot, runtimePlatformDirName(runtimePackage, platform)),
    ),
    packageDir(packageRoot, runtimePackage.name),
  ];
}

async function resolveRuntimePackageVersions({ spec, packageRoot, versionFloors }) {
  for (const runtimePackage of spec.runtime_packages) {
    let resolved = false;
    const startingSequence = versionFloors.get(runtimePackage.name) ?? 0;

    for (let sequence = startingSequence; sequence < 10_000; sequence += 1) {
      const version = wildcardCandidate(runtimePackage.version_spec, sequence);
      setRuntimePackageVersion({
        runtimePackage,
        packageRoot,
        version,
      });

      let conflicts = false;
      for (const dir of runtimePackagePublishDirs(runtimePackage, packageRoot)) {
        const packageJson = readPackageJson(dir);
        const tarball = await npmPack(dir);
        const publishedIntegrity = await npmViewIntegrity(packageJson.name, packageJson.version);

        if (publishedIntegrity !== null && publishedIntegrity !== tarball.integrity) {
          conflicts = true;
          break;
        }
      }

      if (!conflicts) {
        resolved = true;
        break;
      }
    }

    if (!resolved) {
      fail(`ran out of bundle versions for ${runtimePackage.package_name}`);
    }
  }
}

function npmPublish(dir) {
  runCommand("npm", ["publish", "--access", "public", "--registry", NPM_REGISTRY], {
    cwd: dir,
    env: process.env,
  });
}

async function publishPackages({ spec, packageRoot }) {
  const packageDirs = spec.runtime_packages.flatMap((runtimePackage) =>
    runtimePackagePublishDirs(runtimePackage, packageRoot),
  );

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

    npmPublish(dir);
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

function stageCommand(args) {
  stagePackages({
    spec: readSpec(args),
    artifactRoot: requireFlag(args, "--artifact-root"),
    outDir: requireFlag(args, "--out-dir"),
  });
}

async function publishRelease(args) {
  const spec = readSpec(args);
  const outDir = requireFlag(args, "--out-dir");
  const versionFloor = requireFlag(args, "--version-floor");

  stagePackages({
    spec,
    artifactRoot: requireFlag(args, "--artifact-root"),
    outDir,
  });
  await resolveRuntimePackageVersions({
    spec,
    packageRoot: outDir,
    versionFloors: runtimePackageVersionFloors({
      spec,
      versionFloor,
    }),
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
