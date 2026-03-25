#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const { currentPlatformKey, formatSupportedPlatforms } = require("../lib/platform.cjs");

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
const platformKey = currentPlatformKey();
const relativeBinaryPath = pkg.amber.artifacts[platformKey];

if (!relativeBinaryPath) {
  console.error(
    `${pkg.name} does not ship a binary for ${platformKey}. Supported platforms: ${formatSupportedPlatforms(
      Object.keys(pkg.amber.artifacts),
    )}`,
  );
  process.exit(1);
}

const binaryPath = path.join(__dirname, "..", relativeBinaryPath);
const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
  env: process.env,
});

if (result.error) {
  console.error(`failed to execute ${binaryPath}: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  process.kill(process.pid, result.signal);
}

process.exit(result.status ?? 1);
