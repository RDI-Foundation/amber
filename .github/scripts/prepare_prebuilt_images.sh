#!/usr/bin/env bash
set -euo pipefail

if [ -z "${SOURCE_IMAGE_REGISTRY:-}" ]; then
  echo "SOURCE_IMAGE_REGISTRY is required" >&2
  exit 1
fi
if [ -z "${TARGET_IMAGE_REGISTRY:-}" ]; then
  echo "TARGET_IMAGE_REGISTRY is required" >&2
  exit 1
fi
if [ -z "${SOURCE_IMAGE_TAG:-}" ]; then
  echo "SOURCE_IMAGE_TAG is required" >&2
  exit 1
fi

source_image_registry="${SOURCE_IMAGE_REGISTRY%/}"
target_image_registry="${TARGET_IMAGE_REGISTRY%/}"
allow_missing="${ALLOW_MISSING_PREBUILT_IMAGES:-0}"
output_name="${PREBUILT_IMAGES_OUTPUT_NAME:-}"

if [ -n "${VERSION_TAGS_JSON:-}" ]; then
  version_tags_json="${VERSION_TAGS_JSON}"
else
  version_tags_json="$(cargo run -q -p amber-images --bin version_tags -- docker/images.json)"
fi

missing=0
while IFS= read -r spec; do
  [ -z "$spec" ] && continue
  name="$(jq -r '.name' <<< "$spec")"
  version="$(jq -r '.version' <<< "$spec")"
  runtime_tag="$(jq -r '.runtime_tag' <<< "$spec")"
  src="${source_image_registry}/${name}:${SOURCE_IMAGE_TAG}"

  if ! docker pull "$src"; then
    echo "missing prebuilt image: $src" >&2
    missing=1
    continue
  fi

  docker tag "$src" "${target_image_registry}/${name}:${version}"
  if [ "$runtime_tag" != "$version" ]; then
    docker tag "$src" "${target_image_registry}/${name}:${runtime_tag}"
  fi
  if [ "$name" = "amber-helper" ]; then
    docker tag "$src" "amber-helper:e2e"
  fi
done < <(jq -c '.images[]' <<< "$version_tags_json")

if [ "$missing" -ne 0 ]; then
  if [ "$allow_missing" = "1" ]; then
    if [ -n "${GITHUB_OUTPUT:-}" ] && [ -n "$output_name" ]; then
      echo "${output_name}=false" >> "$GITHUB_OUTPUT"
    fi
    exit 0
  fi
  exit 1
fi

if [ -n "${GITHUB_OUTPUT:-}" ] && [ -n "$output_name" ]; then
  echo "${output_name}=true" >> "$GITHUB_OUTPUT"
fi
