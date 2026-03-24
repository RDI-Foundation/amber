#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
const runtimeDir = path.join(__dirname, "..", "runtime-bin");
const entryBinary = path.join(runtimeDir, pkg.amber.entry_binary);

if (!fs.existsSync(entryBinary)) {
  console.error(
    `runtime bundle is missing ${pkg.amber.entry_binary}; run npm rebuild ${pkg.name}`,
  );
  process.exit(1);
}

const env = {
  ...process.env,
  AMBER_RUNTIME_BIN_DIR: runtimeDir,
};

const result = spawnSync(entryBinary, process.argv.slice(2), {
  stdio: "inherit",
  env,
});

if (result.error) {
  console.error(`failed to execute ${entryBinary}: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  process.kill(process.pid, result.signal);
}

process.exit(result.status ?? 1);
