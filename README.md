# RootPermit

RootPermit authorizes one frozen Debian `package.install` transition without
granting an agent a root shell, a sudo credential, or arbitrary command
execution.

This repository implements the security-complete vertical slice defined in
`docs/engineering-spec-v2.md`. The currently supported product boundary is one
native-architecture Debian package name on Ubuntu Server AMD64. Nothing in this
repository authorizes commands, package versions, URLs, paths, repositories,
or APT flags.

## Status

The M3 control-plane contracts are implemented and tested: a root-created
device pairing, hosted account session, verified approval presentation,
broker-verifiable decision relay, revocation quarantine, and fake-execution
projection. This is not the M3 exit gate: the current runtime is an in-memory
contract harness, so a durable hosted adapter and a real broker/relay/browser
end-to-end test remain required before claiming a deployable M3 path.

It does not perform real package installation or make a multi-tenant hosted
alpha claim. M4 (real APT execution) and M5 (multi-tenant hosted alpha) remain
evidence gates until their pinned-VM and PostgreSQL adversarial suites pass.

## Layout

- `crates/`: Rust edge components and shared protocol library
- `helper/apt-helper/`: narrow C++20 `libapt-pkg` helper
- `service/`: TypeScript API, worker, web application, and PostgreSQL schema
- `protocol-vectors/`: versioned conformance and negative test corpus
- `fixtures/`: pinned reference-image definitions
- `docs/`: threat model, API contracts, runbooks, and implementation plan

## Development prerequisites

The authoritative versions are pinned in `rust-toolchain.toml` and `.nvmrc`.
Linux development also requires a C++20 compiler and `libapt-pkg-dev` matching
the target Ubuntu release. See `docs/development.md`.
