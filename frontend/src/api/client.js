const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api';

function errorMessage(detail, status) {
  if (detail && typeof detail === 'object' && !Array.isArray(detail)) {
    const fields = Object.entries(detail.errors || {}).map(([name, msg]) => `${name}: ${msg}`);
    return [detail.message, ...fields].filter(Boolean).join(' — ');
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

export const apiClient = {
  async scanConfigs(files) {
    const formData = new FormData();
    for (const file of files) {
      formData.append('files', file);
    }

    const response = await fetch(`${API_BASE_URL}/scan`, {
      method: 'POST',
      body: formData,
      cache: 'no-cache',
    });

    return handleResponse(response);
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

  getRemediationPlan(scanId, inputs = {}) {
    return postJson('/remediation/plan', { scan_id: scanId, inputs });
  },

  async getExplanation(scanId, ruleId, hostname) {
    const response = await fetch(
      `${API_BASE_URL}/assistant/explain/${scanId}/${ruleId}/${encodeURIComponent(hostname)}`,
      { cache: 'no-cache' }
    );
    return handleResponse(response);
  },

  async getSummary(scanId) {
    const response = await fetch(`${API_BASE_URL}/assistant/summary/${scanId}`, {
      cache: 'no-cache',
    });
    return handleResponse(response);
  },

  async chat(scanId, message) {
    const response = await fetch(`${API_BASE_URL}/assistant/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId, message }),
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

  async downloadFixedConfigs(scanId, inputs = {}) {
    const response = await fetch(`${API_BASE_URL}/download-fixed`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId, inputs }),
      cache: 'no-cache',
    });

    if (!response.ok) await throwApiError(response);

    const contentType = response.headers.get('Content-Type') || '';
    const blob = await response.blob();
    const disposition = response.headers.get('Content-Disposition') || '';
    const filenameMatch = disposition.match(/filename\*?=(?:UTF-8''|"?)([^";\r\n]+)/i);
    const filename = filenameMatch
      ? decodeURIComponent(filenameMatch[1].replace(/^"|"$/g, ''))
      : contentType.toLowerCase().includes('application/zip')
        ? 'NetAuditAI_Fixed_Configs.zip'
        : 'fixed_config.cfg';

    // Keep the response bytes intact so ZIP downloads are never decoded as text.
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },
};
