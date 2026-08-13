import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { validateM4EvidenceContract } from "./m4-evidence-contract.mjs";

const unitText = readFileSync(new URL("../packaging/systemd/rootpermit-apt-helper.service", import.meta.url), "utf8");
const fixture = JSON.parse(readFileSync(new URL("../fixtures/ubuntu-amd64/manifest.json", import.meta.url), "utf8"));

test("M4 systemd boundary remains networkless and sealed-input-only", () => {
  assert.deepEqual(validateM4EvidenceContract({ unitText, fixture }), []);
});

test("ready fixtures cannot omit adversarial evidence requirements", () => {
  const ready = structuredClone(fixture);
  ready.status = "ready";
  ready.sealed_inputs = { required_roles: ["lists"] };
  ready.evidence_bundle = { adversarial_cases: ["TM-10"] };
  assert.match(validateM4EvidenceContract({ unitText, fixture: ready }).join("\n"), /sealed input role/);
  assert.match(validateM4EvidenceContract({ unitText, fixture: ready }).join("\n"), /TM-10 through TM-13/);
});
