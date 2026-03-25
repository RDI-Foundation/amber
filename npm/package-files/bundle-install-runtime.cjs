#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");

const { currentPlatformKey } = require("./platform.cjs");

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
const runtimeDir = path.join(__dirname, "..", "runtime-bin");
const platformKey = currentPlatformKey();

fs.rmSync(runtimeDir, { recursive: true, force: true });
fs.mkdirSync(runtimeDir, { recursive: true });

for (const dependency of pkg.amber.runtime_dependencies) {
  const dependencyPackagePath = require.resolve(`${dependency.package_name}/package.json`);
  const dependencyRoot = path.dirname(dependencyPackagePath);
  const dependencyPackage = JSON.parse(fs.readFileSync(dependencyPackagePath, "utf8"));
  const relativeBinaryPath = dependencyPackage.amber.artifacts[platformKey];

  if (!relativeBinaryPath) {
    throw new Error(
      `${dependency.package_name} does not ship ${dependency.binary_name} for ${platformKey}`,
    );
  }

  const source = path.join(dependencyRoot, relativeBinaryPath);
  const target = path.join(runtimeDir, dependency.binary_name);
  fs.copyFileSync(source, target);
  fs.chmodSync(target, 0o755);
}
