#!/usr/bin/env bash
set -euo pipefail

# The exact package versions are committed in toolchain.lock.json. Discovering
# a newer package is not an upgrade path: the composite action verifies the
# lock after this privileged installation step completes.
apt-get update
apt-get install --yes --no-install-recommends \
  postgresql=16+257build1 \
  postgresql-client=16+257build1
