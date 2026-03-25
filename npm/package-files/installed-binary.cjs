const fs = require("node:fs");
const path = require("node:path");

function resolveInstalledPackage(packageName) {
  const packageJsonPath = require.resolve(`${packageName}/package.json`);
  const packageRoot = path.dirname(packageJsonPath);
  const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));

  return {
    packageRoot,
    packageJson,
  };
}

function resolveInstalledBinary(packageName, binaryName) {
  const { packageRoot, packageJson } = resolveInstalledPackage(packageName);
  const relativeBinaryPath =
    typeof packageJson.bin === "string"
      ? packageJson.bin
      : packageJson.bin?.[binaryName];

  if (!relativeBinaryPath) {
    throw new Error(`${packageName} does not expose ${binaryName}`);
  }

  return path.join(packageRoot, relativeBinaryPath);
}

module.exports = {
  resolveInstalledPackage,
  resolveInstalledBinary,
};
