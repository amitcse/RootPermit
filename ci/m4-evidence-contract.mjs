import { readFileSync } from "node:fs";

const REQUIRED_UNIT_DIRECTIVES = new Map([
  ["NoNewPrivileges", "yes"],
  ["PrivateTmp", "yes"],
  ["PrivateDevices", "yes"],
  ["ProtectSystem", "strict"],
  ["RestrictAddressFamilies", "AF_UNIX"],
  ["IPAddressDeny", "any"],
  ["UMask", "0077"],
  ["CapabilityBoundingSet", "~CAP_SYS_ADMIN"],
]);

const REQUIRED_REPEATABLE_DIRECTIVES = new Map([
  ["Environment", ["LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"]],
  ["SystemCallFilter", ["@system-service", "~@mount"]],
  ["ReadOnlyPaths", ["/var/lib/rootpermit/plans /var/lib/rootpermit/store"]],
  ["ReadWritePaths", ["/var/lib/rootpermit/journal"]],
  [
    "InaccessiblePaths",
    ["/etc/apt /etc/dpkg /var/lib/apt /var/cache/apt /var/lib/dpkg/info /var/lib/dpkg/triggers"],
  ],
]);

const FORBIDDEN_DIRECTIVES = new Set([
  "AmbientCapabilities",
  "BindPaths",
  "BindReadOnlyPaths",
  "EnvironmentFile",
  "ExecSearchPath",
  "PassEnvironment",
  "RootDirectory",
  "RootImage",
  "SetLoginEnvironment",
  "TemporaryFileSystem",
  "UnsetEnvironment",
]);

export function validateM4EvidenceContract({ unitText, fixture }) {
  const errors = [];
  const directives = new Map();
  for (const [name, value] of unitText
      .split(/\r?\n/)
      .filter((line) => !line.trimStart().startsWith("#") && line.includes("="))
      .map((line) => {
        const separator = line.indexOf("=");
        return [line.slice(0, separator).trim(), line.slice(separator + 1).trim()];
      })) {
    const values = directives.get(name) ?? [];
    values.push(value);
    directives.set(name, values);
  }
  for (const [name, value] of REQUIRED_UNIT_DIRECTIVES) {
    const values = directives.get(name) ?? [];
    if (values.length !== 1 || values[0] !== value) errors.push(`systemd ${name} must be ${value}`);
  }
  for (const [name, expected] of REQUIRED_REPEATABLE_DIRECTIVES) {
    const actual = directives.get(name) ?? [];
    if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index])) {
      errors.push(`systemd ${name} must contain only the sealed-helper policy values`);
    }
  }
  for (const name of FORBIDDEN_DIRECTIVES) {
    if (directives.has(name)) errors.push(`systemd ${name} is not permitted for the sealed helper`);
  }
  if (fixture.status === "ready") {
    const sealed = fixture.sealed_inputs;
    const evidence = fixture.evidence_bundle;
    if (!sealed || !Array.isArray(sealed.required_roles) || sealed.required_roles.length < 5) {
      errors.push("ready M4 fixture must declare every sealed input role");
    }
    if (!evidence || !Array.isArray(evidence.adversarial_cases) || !["TM-10", "TM-11", "TM-12", "TM-13"].every((id) => evidence.adversarial_cases.includes(id))) {
      errors.push("ready M4 fixture must retain TM-10 through TM-13 evidence");
    }
  }
  return errors;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const fixture = JSON.parse(readFileSync(process.argv[2] ?? "fixtures/ubuntu-amd64/manifest.json", "utf8"));
  const unitText = readFileSync(process.argv[3] ?? "packaging/systemd/rootpermit-apt-helper.service", "utf8");
  const errors = validateM4EvidenceContract({ unitText, fixture });
  if (errors.length > 0) throw new Error(errors.join("\n"));
  console.log("M4 sandbox and fixture contract verified");
}
