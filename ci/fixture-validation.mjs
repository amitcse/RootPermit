const SHA256 = /^[a-f0-9]{64}$/;
const SNAPSHOT = /^\d{8}T\d{6}Z$/;
const KERNEL = /^\d+\.\d+\.\d+-\d+-generic$/;

function problem(path, message) {
  return `${path}: ${message}`;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validateFixtureManifest(manifest, source = "manifest") {
  const errors = [];
  if (!isObject(manifest)) return [problem(source, "must be an object")];
  const status = manifest.status;
  if (!new Set(["contract-only", "provisioning-ready", "ready"]).has(status)) {
    errors.push(problem(`${source}.status`, "must be contract-only, provisioning-ready, or ready"));
  }
  if (!isObject(manifest.platform) || manifest.platform.architecture !== "amd64" && manifest.platform.architecture !== "arm64") {
    errors.push(problem(`${source}.platform`, "must declare amd64 or arm64 architecture"));
  }
  if (typeof manifest.fixture_id !== "string" || !/^[a-z0-9][a-z0-9-]{2,63}$/.test(manifest.fixture_id)) {
    errors.push(problem(`${source}.fixture_id`, "must be a stable lowercase fixture identifier"));
  }
  if (status === "contract-only") {
    for (const prohibited of ["image", "runtime", "apt_repositories", "artifact_retention", "sealed_inputs", "evidence_bundle"]) {
      if (prohibited in manifest) errors.push(problem(`${source}.${prohibited}`, "is forbidden for contract-only"));
    }
    return errors;
  }
  const image = manifest.image;
  if (!isObject(image) || typeof image.locator !== "string" || !image.locator.startsWith("https://") ||
      typeof image.publisher_checksum_url !== "string" || !image.publisher_checksum_url.startsWith("https://") ||
      image.format !== "qcow2" || !SHA256.test(image.sha256 ?? "")) {
    errors.push(problem(`${source}.image`, "must be an HTTPS QCOW2 locator with a SHA-256 and publisher checksum URL"));
  }
  const runtime = manifest.runtime;
  if (!isObject(runtime) || !KERNEL.test(runtime.kernel ?? "") ||
      typeof runtime.apt_version !== "string" || runtime.apt_version.length === 0 ||
      typeof runtime.dpkg_version !== "string" || runtime.dpkg_version.length === 0) {
    errors.push(problem(`${source}.runtime`, "must declare kernel, APT version, and dpkg version"));
  }
  if (!Array.isArray(manifest.apt_repositories) || manifest.apt_repositories.length === 0 ||
      manifest.apt_repositories.some((repository) => !isObject(repository) ||
        typeof repository.uri !== "string" || !repository.uri.startsWith("https://") ||
        typeof repository.suite !== "string" || !Array.isArray(repository.components) || repository.components.length === 0 ||
        !SNAPSHOT.test(repository.snapshot_id ?? ""))) {
    errors.push(problem(`${source}.apt_repositories`, "must declare HTTPS snapshot repositories"));
  }
  const retention = manifest.artifact_retention;
  if (!isObject(retention) || typeof retention.path !== "string" || !retention.path.startsWith("artifacts/") ||
      !Number.isInteger(retention.retention_days) || retention.retention_days < 7 || retention.retention_days > 90) {
    errors.push(problem(`${source}.artifact_retention`, "must declare an artifact path and 7-90 day retention"));
  }
  if (status === "ready" && (!isObject(manifest.sealed_inputs) || !isObject(manifest.evidence_bundle))) {
    errors.push(problem(source, "ready fixtures require sealed_inputs and evidence_bundle"));
  }
  return errors;
}
