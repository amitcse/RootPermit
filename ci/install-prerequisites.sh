#!/usr/bin/env bash
set -euo pipefail

# The exact package versions are committed in toolchain.lock.json.  Discovering
# a newer package is not an upgrade path: verification below fails closed until
# the lock and its review are updated together.
apt-get update
# ubuntu-24.04 runner images can update `apt` before their package mirrors drop
# the matching development headers.  Pinning only libapt-pkg-dev then leaves
# the newer `apt` package holding its newer library, which makes APT reject the
# otherwise available locked development package.  Install the complete APT
# lock set together (and explicitly permit that controlled downgrade).
apt-get install --yes --no-install-recommends --allow-downgrades \
  apt=2.7.14build2 \
  libapt-pkg-dev=2.7.14build2 \
  postgresql=16+257build1 \
  postgresql-client=16+257build1

node ci/verify-toolchain.mjs
