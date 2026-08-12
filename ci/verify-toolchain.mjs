import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const lock = JSON.parse(readFileSync(new URL("./toolchain.lock.json", import.meta.url)));

function fail(message) {
  throw new Error(`toolchain prerequisite failed: ${message}`);
}

function command(command, args) {
  try {
    return execFileSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch {
    fail(`${command} is unavailable`);
  }
}

function installedVersion(packageName) {
  return command("dpkg-query", ["--show", "--showformat=${Version}", packageName]);
}

const rust = command("cargo", ["--version"]);
if (!rust.includes(` ${lock.rust} `)) fail(`cargo must be ${lock.rust}, got ${rust}`);

const node = command("node", ["--version"]);
if (node !== `v${lock.node}`) fail(`node must be ${lock.node}, got ${node}`);

const cmake = command("cmake", ["--version"]);
const cmakeVersion = cmake.match(/version\s+([^\s]+)/)?.[1];
if (cmakeVersion !== lock.cmake) {
  fail(`CMake must be ${lock.cmake}, got ${cmake}`);
}

command("ctest", ["--version"]);
command("psql", ["--version"]);
const postgresPath = command("pg_config", ["--bindir"]);
command(`${postgresPath}/postgres`, ["--version"]);

for (const [packageName, expected] of [
  ["postgresql", lock.postgres],
  ["postgresql-client", lock.postgres],
]) {
  const actual = installedVersion(packageName);
  if (actual !== expected) fail(`${packageName} must be ${expected}, got ${actual}`);
}

console.log("RootPermit P0 toolchain lock verified");
