import assert from "node:assert/strict";
import test from "node:test";
import { selectLanes } from "./lane-selection.mjs";

test("M4 changes always select the privileged lane", () => {
  const lanes = selectLanes(["helper/apt-helper/src/main.cpp"]);
  assert.equal(lanes.m4, true);
  assert.equal(lanes.privileged, true);
  assert.equal(lanes.postgres, false);
});

test("M5 changes always select PostgreSQL integration", () => {
  const lanes = selectLanes(["service/migrations/0004_tenant_cache.sql"]);
  assert.equal(lanes.m5, true);
  assert.equal(lanes.postgres, true);
});

test("CI and fixture-routing changes select both affected lanes", () => {
  const lanes = selectLanes(["ci/lane-selection.mjs"]);
  assert.equal(lanes.postgres, true);
  assert.equal(lanes.privileged, true);
});

test("nightly always selects the privileged lane even without changed paths", () => {
  assert.equal(selectLanes([], { eventName: "schedule" }).privileged, true);
});

test("release candidates select all blocking evidence lanes", () => {
  const lanes = selectLanes(["README.md"], { eventName: "workflow_dispatch", releaseCandidate: true });
  assert.equal(lanes.fast, true);
  assert.equal(lanes.postgres, true);
  assert.equal(lanes.privileged, true);
  assert.equal(lanes.release, true);
});
