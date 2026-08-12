import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { validateFixtureManifest } from "./fixture-validation.mjs";

const ubuntu = JSON.parse(readFileSync("fixtures/ubuntu-amd64/manifest.json", "utf8"));

test("the AMD64 fixture is provisioning-ready and fully pinned", () => {
  assert.deepEqual(validateFixtureManifest(ubuntu), []);
  assert.equal(ubuntu.status, "provisioning-ready");
  assert.match(ubuntu.image.sha256, /^[a-f0-9]{64}$/);
  assert.equal(ubuntu.platform.architecture, "amd64");
});

test("a provisioning fixture cannot omit a runtime, repository, or retention declaration", () => {
  for (const field of ["runtime", "apt_repositories", "artifact_retention"]) {
    const candidate = structuredClone(ubuntu);
    delete candidate[field];
    assert.notDeepEqual(validateFixtureManifest(candidate), [], field);
  }
});

test("a ready fixture cannot be used without M4 sealed inputs and evidence", () => {
  const candidate = structuredClone(ubuntu);
  candidate.status = "ready";
  assert.match(validateFixtureManifest(candidate).join("\n"), /sealed_inputs and evidence_bundle/);
});
