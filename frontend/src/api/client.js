const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api';

// A request that never reached the server (backend stopped or restarting, network down) says so in words
// instead of the browser's "Failed to fetch". status 0: no HTTP answer at all.
export const UNREACHABLE = 'Can’t reach the NetAuditAI server. Check that the backend is running, then try again.';
async function fetch(url, options) {
  try {
    return await globalThis.fetch(url, options);
  } catch {
    const err = new Error(UNREACHABLE);
    err.status = 0;
    throw err;
  }
}

function errorMessage(detail, status) {
  if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
    const fields = Object.entries(detail.errors || {}).map(([name, msg]) => `${name}: ${msg}`);
    return fields.length ? `${detail.message || 'Please check what you entered'}. ${fields.join('. ')}.`
      : (detail.message || `API error: ${status}`);
  }
  return (typeof detail === 'string' && detail) || `API error: ${status}`;
}

// Errors carry the HTTP status: a 404 on a scan means the backend no longer holds it
async function throwApiError(response) {
  const error = await response.json().catch(() => ({ detail: response.statusText }));
  const err = new Error(errorMessage(error.detail, response.status));
  err.status = response.status;
  throw err;
}

async function handleResponse(response) {
  if (!response.ok) await throwApiError(response);
  return response.json();
}

async function postJson(path, body) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    cache: 'no-cache',
  });
  return handleResponse(response);
}

// Post, then save the response as a file.
async function saveDownload(path, body) {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    cache: 'no-cache',
  });
  if (!response.ok) await throwApiError(response);

  const contentType = response.headers.get('Content-Type') || '';
  const blob = await response.blob();
  const disposition = response.headers.get('Content-Disposition') || '';
  const filenameMatch = disposition.match(/filename\*?=(?:UTF-8''|"?)([^";\r\n]+)/i);
  const filename = filenameMatch
    ? decodeURIComponent(filenameMatch[1].replace(/^"|"$/g, ''))
    : contentType.toLowerCase().includes('application/pdf')
      ? 'NetAuditAI_Compliance_Report.pdf'
      : contentType.toLowerCase().includes('application/zip')
        ? 'NetAuditAI_Fixed_Configs.zip'
        : 'fixed_config.cfg';

  // Keep the response bytes intact so ZIP downloads are never decoded as text.
  saveBlob(blob, filename);
}

function saveBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export const apiClient = {
  // context: { criticality, internetFacing } the operator states about the asset (risk only)
  async scanConfigs(files, framework = null, context = {}) {
    const formData = new FormData();
    for (const file of files) {
      formData.append('files', file);
    }
    if (framework) formData.append('framework', framework);
    if (context.criticality) formData.append('criticality', context.criticality);
    if (context.internetFacing) formData.append('internet_facing', 'true');
    if (context.policy) formData.append('policy', context.policy);

    const response = await fetch(`${API_BASE_URL}/scan`, {
      method: 'POST',
      body: formData,
      cache: 'no-cache',
    });

    return handleResponse(response);
  },

  // What this backend can collect from, and whether collection is enabled at all. Never throws for
  // "disabled" or "driver missing": those are answers the form shows, not failures.
  async getCollectCapabilities() {
    const response = await fetch(`${API_BASE_URL}/collect/capabilities`, { cache: 'no-cache' });
    return handleResponse(response);
  },

  // Pull configurations off live devices and scan them. Credentials are sent for this one request
  // and are never stored by the backend; they are not kept in the browser either.
  async collectConfigs(targets, framework = null) {
    return postJson('/collect', { targets, framework: framework || null });
  },

  // Every check and the framework requirements it answers
  async getCatalog() {
    return handleResponse(await fetch(`${API_BASE_URL}/catalog`, { cache: 'no-cache' }));
  },

  // The audit ledger (app/ledger.py)
  async getLedger(limit = 100) {
    return handleResponse(await fetch(`${API_BASE_URL}/ledger?limit=${limit}`, { cache: 'no-cache' }));
  },

  async verifyLedger() {
    return handleResponse(await fetch(`${API_BASE_URL}/ledger/verify`, { cache: 'no-cache' }));
  },

  async verifyReport(file) {
    const body = new FormData();
    body.append('file', file);
    return handleResponse(await fetch(`${API_BASE_URL}/ledger/verify-report`, { method: 'POST', body }));
  },

  async getScan(scanId) {
    const response = await fetch(`${API_BASE_URL}/scan/${scanId}`, {
      cache: 'no-cache',
    });
    return handleResponse(response);
  },

  // true when the backend still holds the scan, false when it was cleared (restart); throws if unreachable
  async isScanHeld(scanId) {
    const response = await fetch(`${API_BASE_URL}/scan/${scanId}/status`, { cache: 'no-cache' });
    return (await handleResponse(response)).held === true;
  },

  // Deterministic remediation of one control on one uploaded config (config_index is the identity;
  // hostnames can repeat), verified by a rescan. No command text is ever sent.
  getRemediation(scanId, ruleId, deviceHostname, configIndex, inputs = {}) {
    return postJson('/remediate', {
      scan_id: scanId,
      rule_id: ruleId,
      device_hostname: deviceHostname,
      config_index: configIndex,
      inputs,
    });
  },

  // deviceInputs: each device's own values, by config index ({ 0: { ntp_key: … } })
  getRemediationPlan(scanId, deviceInputs = {}) {
    return postJson('/remediation/plan', { scan_id: scanId, device_inputs: deviceInputs });
  },

  // The score once every fix you decided on is in: verified fixes plus the candidates you confirmed
  async remediationFinal(scanId, deviceInputs = {}) {
    return postJson('/remediation/final', { scan_id: scanId, device_inputs: deviceInputs });
  },

  // Candidate remediation for a device whose vendor is not confirmed. `action` is 'propose' (the
  // command an administrator typed), 'generate' (ask the AI for one), 'verify' (simulate it on a copy of the
  // uploaded configuration), 'confirm' or 'reject'. Command text is never executed and never sent to a device.
  remediationCandidate(action, scanId, ruleId, deviceHostname, configIndex, body = {}) {
    return postJson(`/remediation/candidate${action === 'propose' ? '' : `/${action}`}`, {
      scan_id: scanId,
      rule_id: ruleId,
      device_hostname: deviceHostname,
      config_index: configIndex,
      ...body,
    });
  },

  async getExplanation(scanId, ruleId, hostname) {
    const response = await fetch(
      `${API_BASE_URL}/assistant/explain/${scanId}/${ruleId}/${encodeURIComponent(hostname)}`,
      { cache: 'no-cache' }
    );
    return handleResponse(response);
  },

  async getAssistantStatus() {
    const response = await fetch(`${API_BASE_URL}/assistant/status`, { cache: 'no-cache' });
    return handleResponse(response);
  },

  async getSummary(scanId) {
    const response = await fetch(`${API_BASE_URL}/assistant/summary/${scanId}`, {
      cache: 'no-cache',
    });
    return handleResponse(response);
  },

  // The backend reads the scan's own redacted results as context; history lets a follow-up
  // ("why?", "and the other one?") refer back. It is sent, never stored server-side.
  async chat(scanId, message, history = []) {
    const response = await fetch(`${API_BASE_URL}/assistant/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId, message, history }),
      cache: 'no-cache',
    });
    return handleResponse(response);
  },

  // --- Adaptive training ---

  async getNormalizedFields() {
    const response = await fetch(`${API_BASE_URL}/adaptive/fields`, { cache: 'no-cache' });
    return handleResponse(response);
  },

  async getReviewQueue(scanId, includeResolved = false) {
    const response = await fetch(
      `${API_BASE_URL}/adaptive/scans/${scanId}/review?include_resolved=${includeResolved}`,
      { cache: 'no-cache' }
    );
    return handleResponse(response);
  },

  async acceptInterpretation(scanId, itemId, body = {}) {
    const response = await fetch(`${API_BASE_URL}/adaptive/scans/${scanId}/review/${itemId}/accept`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      cache: 'no-cache',
    });
    return handleResponse(response);
  },

  async editInterpretation(scanId, itemId, body) {
    const response = await fetch(`${API_BASE_URL}/adaptive/scans/${scanId}/review/${itemId}/edit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      cache: 'no-cache',
    });
    return handleResponse(response);
  },

  async rejectInterpretation(scanId, itemId, reason = null) {
    const response = await fetch(`${API_BASE_URL}/adaptive/scans/${scanId}/review/${itemId}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
      cache: 'no-cache',
    });
    return handleResponse(response);
  },

  // --- Provisional results → recognizers ---

  async getProvisionalResults(scanId) {
    const response = await fetch(`${API_BASE_URL}/adaptive/scans/${scanId}/provisional`, { cache: 'no-cache' });
    return handleResponse(response);
  },

  // Controls the scan could not decide, with the lines a person can teach from
  async getUnresolvedControls(scanId) {
    const response = await fetch(`${API_BASE_URL}/adaptive/scans/${scanId}/unresolved`, { cache: 'no-cache' });
    return handleResponse(response);
  },

  // The uploaded configuration as it was uploaded, redacted for display. Read-only: teaching cites a
  // line of it, and nothing in the API writes it back.
  // Ask the AI which line answers one undecided check (redacted lines only; a person still confirms it)
  async askAI(scanId, configIndex, controlId) {
    return postJson(`/adaptive/scans/${scanId}/ask-ai`, { config_index: configIndex, control_id: controlId });
  },

  async getConfigLines(scanId, configIndex) {
    const response = await fetch(`${API_BASE_URL}/adaptive/scans/${scanId}/configs/${configIndex}/lines`, { cache: 'no-cache' });
    return handleResponse(response);
  },

  // What a person may say one line means for one control
  async getMeaningOptions(scanId, { controlId, lineNumber, configIndex = 0 }) {
    const query = new URLSearchParams({ control_id: controlId, line_number: lineNumber, config_index: configIndex });
    const response = await fetch(`${API_BASE_URL}/adaptive/scans/${scanId}/meanings?${query}`, { cache: 'no-cache' });
    return handleResponse(response);
  },

  draftRecognizer(scanId, body) {
    return postJson(`/adaptive/scans/${scanId}/recognizers/draft`, body);
  },

  saveRecognizer(scanId, body) {
    return postJson(`/adaptive/scans/${scanId}/recognizers`, body);
  },

  rejectProvisionalLine(scanId, body) {
    return postJson(`/adaptive/scans/${scanId}/provisional/reject`, body);
  },

  async listLearnedMappings(includeInactive = false) {
    const response = await fetch(
      `${API_BASE_URL}/adaptive/mappings?include_inactive=${includeInactive}`,
      { cache: 'no-cache' }
    );
    return handleResponse(response);
  },

  async disableLearnedMapping(mappingId) {
    const response = await fetch(`${API_BASE_URL}/adaptive/mappings/${mappingId}`, {
      method: 'DELETE',
      cache: 'no-cache',
    });
    return handleResponse(response);
  },

  // The vendor-neutral Security Baseline Model of every device of the scan, saved as one JSON file
  // One device's vendor-neutral Security Baseline Model
  // Changes since the last audit of the same devices (app/analysis/drift.py)
  async getDrift(scanId) {
    return handleResponse(await fetch(`${API_BASE_URL}/scan/${scanId}/drift`, { cache: 'no-cache' }));
  },

  async getBaseline(scanId, configIndex = 0) {
    const response = await fetch(`${API_BASE_URL}/scan/${scanId}/baseline?config_index=${configIndex}`, { cache: 'no-cache' });
    return handleResponse(response);
  },

  async downloadBaseline(scanId, devices = 1) {
    const models = [];
    for (let i = 0; i < devices; i += 1) models.push(await this.getBaseline(scanId, i));
    const body = JSON.stringify(devices === 1 ? models[0] : { devices: models }, null, 2);
    saveBlob(new Blob([body], { type: 'application/json' }), `NetAuditAI_Baseline_${scanId.slice(0, 8)}.json`);
  },

  // The compliance report as PDF (one device, or every device of the scan as a .zip)
  // variant 'executive': the one-page summary instead of the full technical report
  async downloadReport(scanId, configIndex = null, inputs = {}, variant = 'full') {
    await saveDownload('/report', { scan_id: scanId, config_index: configIndex, inputs, variant });
  },

  async downloadFixedConfigs(scanId, deviceInputs = {}, includeConfirmed = false) {
    await saveDownload('/download-fixed', { scan_id: scanId, device_inputs: deviceInputs, include_confirmed: includeConfirmed });
  },

  // The verified corrected COPY of the uploaded configuration for one candidate (unconfirmed vendor).
  // The backend refuses anything that is not verified, so an unverified candidate can never be saved.
  async downloadCandidateConfig(scanId, ruleId, deviceHostname, configIndex) {
    await saveDownload('/remediation/candidate/download', {
      scan_id: scanId,
      rule_id: ruleId,
      device_hostname: deviceHostname,
      config_index: configIndex,
    });
  },
};
