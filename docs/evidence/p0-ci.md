# P0 CI and fixture evidence

P0 makes the following evidence gates reproducible without treating any of them
as authorization to execute APT.

## Pinned toolchain

`ci/toolchain.lock.json` is the authoritative Linux CI lock. The composite
action `ci/setup-toolchain` installs the declared APT development and PostgreSQL
packages, then `ci/verify-toolchain.mjs` rejects a missing or version-mismatched
Rust, Node, CMake/CTest, APT development package, PostgreSQL client, or
PostgreSQL server. A toolchain update is a reviewed lock update; CI must not
silently accept a newer runner package.

The installer applies the `apt` runtime and `libapt-pkg-dev` header lock as one
set. This is necessary on hosted runner images: a newer preinstalled `apt`
holds a newer `libapt-pkg`, while the locked development headers require the
matching locked library. The installer makes that reviewed downgrade explicit
rather than silently relaxing the lock.

The normal helper-contract build intentionally runs with
`RP_APT_HELPER_BUILD_M4_TARGETS=OFF`. Setting it to `ON` makes CMake require the
`libapt-pkg` headers and library. That mode is only a dependency sentinel until
the M4 simulation and fixture evidence exist.

## Fixture stages

The AMD64 manifest is `provisioning-ready`, not `ready`. Its checksum-pinned
Canonical QCOW2 base, native architecture, kernel, APT/dpkg versions, snapshot
repository identity, and 30-day artifact retention are schema-validated by:

```sh
npm ci
npm run ci:contract
```

The nightly workflow runs the same validation, downloads only this pinned image
on an explicitly declared privileged fixture runner, checks SHA-256, and retains
the provisioning log (including a failed download/checksum) for 30 days. The
provisioner never starts a VM or invokes APT. M4 may change the fixture to
`ready` only together with sealed inputs, evidence metadata, and its adversarial
execution matrix.

## Lane policy

`ci/lane-selection.mjs` is unit-tested. Its policy is deliberately conservative:

- M4 helper or fixture changes select privileged fixture preflight and nightly evidence.
- M5 service/migration changes select the live PostgreSQL integration lane.
- Changes to CI routing select both lanes.
- A release candidate selects fast, PostgreSQL, and privileged lanes regardless
  of the changed-path set.

Repository branch protection must require **Fast PR evidence**, **PostgreSQL
integration PR** when selected, and **Privileged fixture preflight** when
selected. Release-candidate promotion additionally requires a green privileged
nightly evidence run for the promoted commit.
