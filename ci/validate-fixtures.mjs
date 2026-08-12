import Ajv2020 from "ajv/dist/2020.js";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { validateFixtureManifest } from "./fixture-validation.mjs";

const root = process.argv[2] ?? "fixtures";
const schema = JSON.parse(readFileSync(join(root, "fixture-manifest.schema.json"), "utf8"));
// The schema's conditional `not/required` clauses intentionally refer to
// top-level properties declared beside the condition. Ajv's strictRequired
// heuristic cannot express that relationship, while normal strict validation
// remains enabled for every instance rule.
const schemaValidator = new Ajv2020({ allErrors: true, strict: true, strictRequired: false }).compile(schema);
const manifests = readdirSync(root, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => join(root, entry.name, "manifest.json"));
const errors = manifests.flatMap((path) => {
  try {
    const manifest = JSON.parse(readFileSync(path, "utf8"));
    const schemaErrors = schemaValidator(manifest) ? [] : (schemaValidator.errors ?? [])
      .map((error) => `${path}${error.instancePath || "/"}: ${error.message ?? "schema validation failed"}`);
    return [...schemaErrors, ...validateFixtureManifest(manifest, path)];
  } catch (error) {
    return [`${path}: invalid JSON: ${error.message}`];
  }
});
if (errors.length > 0) throw new Error(`fixture validation failed:\n${errors.join("\n")}`);
console.log(`validated ${manifests.length} fixture manifest(s)`);
