#!/usr/bin/env bash
set -euo pipefail

fixture_path="${1:-fixtures/ubuntu-amd64/manifest.json}"
artifact_root="${2:-artifacts/privileged}"

node ci/validate-fixtures.mjs fixtures

if [[ "${RP_PRIVILEGED_FIXTURE_RUNNER:-}" != "1" ]]; then
  echo "refusing fixture download outside a declared privileged runner" >&2
  exit 78
fi

fixture_id="$(node -e 'const m=require(process.argv[1]); process.stdout.write(m.fixture_id)' "$fixture_path")"
image_url="$(node -e 'const m=require(process.argv[1]); process.stdout.write(m.image.locator)' "$fixture_path")"
image_sha="$(node -e 'const m=require(process.argv[1]); process.stdout.write(m.image.sha256)' "$fixture_path")"
target_dir="$artifact_root/$fixture_id"
mkdir -p "$target_dir"
curl --fail --location --proto '=https' --tlsv1.2 --output "$target_dir/base.qcow2" "$image_url"
printf '%s  %s\n' "$image_sha" "$target_dir/base.qcow2" | sha256sum --check --strict
printf 'fixture=%s\nimage_sha256=%s\n' "$fixture_id" "$image_sha" > "$target_dir/provisioning.txt"
echo "provisioned checksum-verified fixture evidence at $target_dir"
