#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const { currentPlatformKey, formatSupportedPlatforms } = require("../lib/platform.cjs");
const { resolveInstalledBinary, resolveInstalledPackage } = require("../lib/installed-binary.cjs");

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
const platformKey = currentPlatformKey();
const packageName = pkg.amber.platform_packages[platformKey];

if (!packageName) {
  console.error(
    `${pkg.name} does not ship ${pkg.amber.entry_binary} for ${platformKey}. Supported platforms: ${formatSupportedPlatforms(
      Object.keys(pkg.amber.platform_packages),
    )}`,
  );
  process.exit(1);
}

const { packageRoot, packageJson } = resolveInstalledPackage(packageName);
const binaryPath = resolveInstalledBinary(packageName, pkg.amber.entry_binary);
const env = { ...process.env };
const runtimeBinDir = packageJson.amber?.runtime_bin_dir;

if (runtimeBinDir && !("AMBER_RUNTIME_BIN_DIR" in process.env)) {
  env.AMBER_RUNTIME_BIN_DIR = path.join(packageRoot, runtimeBinDir);
}

const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env,
});

if (result.error) {
  console.error(`failed to execute ${binaryPath}: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  process.kill(process.pid, result.signal);
}

process.exit(result.status ?? 1);
