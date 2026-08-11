import type { ApprovalPage } from "./approval-page.ts";

/** A small SSR/static renderer; untrusted values are always text-escaped. */
export function renderApprovalHtml(page: ApprovalPage): string {
  if (page.kind === "blocked") {
    return `<main class="approval blocked" aria-live="assertive"><p class="eyebrow">Approval unavailable</p><h1>${escapeHtml(page.heading)}</h1><p>${escapeHtml(page.message)}</p><p class="code">${page.code}</p></main>`;
  }
  const c = page.consequences;
  const list = (changes: readonly { readonly name: string; readonly version: string }[]) => changes.length === 0
    ? "None"
    : changes.map((change) => `<li><strong>${escapeHtml(change.name)}</strong> ${escapeHtml(change.version)}</li>`).join("");
  const note = page.untrustedAgentNote === null ? "" : `<aside class="agent-note" aria-label="Untrusted agent explanation"><h2>Agent explanation (untrusted)</h2><p>${escapeHtml(page.untrustedAgentNote.text)}</p></aside>`;
  return `<main class="approval"><header><p class="eyebrow">Approval required</p><h1>Install ${escapeHtml(c.target.name)} on ${escapeHtml(page.request.device)}</h1></header><section class="consequences" aria-label="Broker-verified package consequences"><h2>Broker-verified transaction</h2><dl><dt>Target</dt><dd>${escapeHtml(c.target.name)} ${escapeHtml(c.target.version)}</dd><dt>Dependencies</dt><dd>${list(c.dependencies)}</dd><dt>Removals</dt><dd>${list(c.removals)}</dd><dt>Downgrades</dt><dd>${list(c.downgrades)}</dd><dt>Origin</dt><dd>${escapeHtml(c.origin)}</dd><dt>Archive impact</dt><dd>${c.archiveBytes} bytes</dd><dt>Disk impact</dt><dd>${c.diskBytes} bytes</dd><dt>Policy</dt><dd>${escapeHtml(page.request.policy)}</dd><dt>Request digest</dt><dd><code>${page.request.digest}</code></dd></dl></section>${note}<p class="expiry">Expires at ${new Date(page.request.expiresAtUnixMs).toISOString()}</p><div class="actions"><button type="button" data-decision="deny">Deny with passkey</button><button type="button" data-decision="approve">Approve with passkey</button></div></main>`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" })[character]!);
}
