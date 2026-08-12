#!/usr/bin/env bash
set -euo pipefail

# The exact package versions are committed in toolchain.lock.json.  Discovering
# a newer package is not an upgrade path: verification below fails closed until
# the lock and its review are updated together.
apt-get update
apt-get install --yes --no-install-recommends \
  libapt-pkg-dev=2.7.14build2 \
  postgresql=16+257build1 \
  postgresql-client=16+257build1

node ci/verify-toolchain.mjs
