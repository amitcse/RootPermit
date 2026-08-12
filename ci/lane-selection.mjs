const LANE_PATTERNS = {
  postgres: ["service/", "service/migrations/", "ci/", ".github/workflows/ci.yml"],
  privileged: ["helper/apt-helper/", "fixtures/", "ci/", ".github/workflows/ci.yml", ".github/workflows/privileged-nightly.yml"],
  release: ["Cargo.toml", "Cargo.lock", "package.json", "package-lock.json", "rust-toolchain.toml", "helper/", "fixtures/", "service/", "ci/", ".github/"],
};

function matches(path, prefix) {
  return path === prefix || path.startsWith(prefix);
}

function changed(paths, patterns) {
  return paths.some((path) => patterns.some((pattern) => matches(path, pattern)));
}

export function selectLanes(paths, { eventName = "pull_request", releaseCandidate = false } = {}) {
  if (!Array.isArray(paths) || paths.some((path) => typeof path !== "string" || path.length === 0)) {
    throw new Error("changed paths must be a list of non-empty repository-relative paths");
  }
  const m5 = changed(paths, ["service/", "service/migrations/"]);
  const m4 = changed(paths, ["helper/apt-helper/", "fixtures/"]);
  return {
    fast: eventName !== "schedule" && eventName !== "release",
    postgres: releaseCandidate || eventName === "release" ||
      eventName === "pull_request" && changed(paths, LANE_PATTERNS.postgres),
    privileged: releaseCandidate || eventName === "release" || eventName === "schedule" ||
      m4 || changed(paths, ["ci/"]),
    release: releaseCandidate || eventName === "release",
    m4,
    m5,
  };
}

function main() {
  const args = process.argv.slice(2);
  const paths = args.length === 1 && args[0] === "--stdin"
    ? readFileSync(0, "utf8").split("\n").filter(Boolean)
    : args;
  const lanes = selectLanes(paths, {
    eventName: process.env.GITHUB_EVENT_NAME ?? "pull_request",
    releaseCandidate: process.env.ROOTPERMIT_RELEASE_CANDIDATE === "1",
  });
  if (process.env.GITHUB_OUTPUT) {
    for (const [name, value] of Object.entries(lanes)) {
      process.stdout.write(`${name}=${value}\n`);
    }
  } else {
    process.stdout.write(`${JSON.stringify(lanes)}\n`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
import { readFileSync } from "node:fs";
