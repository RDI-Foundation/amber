function currentPlatformKey() {
  return `${process.platform}-${process.arch}`;
}

function formatSupportedPlatforms(platforms) {
  return platforms.sort().join(", ");
}

module.exports = {
  currentPlatformKey,
  formatSupportedPlatforms,
};
