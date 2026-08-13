import { readFileSync } from "node:fs";

const REQUIRED_UNIT_DIRECTIVES = new Map([
  ["NoNewPrivileges", "yes"],
  ["PrivateTmp", "yes"],
  ["PrivateDevices", "yes"],
  ["ProtectSystem", "strict"],
  ["RestrictAddressFamilies", "AF_UNIX"],
  ["IPAddressDeny", "any"],
  ["UMask", "0077"],
]);

export function validateM4EvidenceContract({ unitText, fixture }) {
  const errors = [];
  const directives = new Map(
    unitText
      .split(/\r?\n/)
      .filter((line) => !line.startsWith("#") && line.includes("="))
      .map((line) => {
        const separator = line.indexOf("=");
        return [line.slice(0, separator), line.slice(separator + 1)];
      }),
  );
  for (const [name, value] of REQUIRED_UNIT_DIRECTIVES) {
    if (directives.get(name) !== value) errors.push(`systemd ${name} must be ${value}`);
  }
  if (directives.get("Environment") !== "PATH=/usr/sbin:/usr/bin:/sbin:/bin") {
    errors.push("systemd helper must have an exact broker-compatible PATH");
  }
  if (!unitText.includes("ReadOnlyPaths=/var/lib/rootpermit/plans /var/lib/rootpermit/store")) {
    errors.push("systemd helper must expose only sealed plan and store inputs read-only");
  }
  if (!unitText.includes("ReadWritePaths=/var/lib/rootpermit/journal")) {
    errors.push("systemd helper must constrain writes to the execution journal");
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
