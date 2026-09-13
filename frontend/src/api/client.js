const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api';

async function handleResponse(response) {
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || `API error: ${response.status}`);
  }
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

  async getRemediation(scanId, ruleId, deviceHostname) {
    const response = await fetch(`${API_BASE_URL}/remediate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scan_id: scanId,
        rule_id: ruleId,
        device_hostname: deviceHostname,
      }),
      cache: 'no-cache',
    });

    return handleResponse(response);
  },

  async verifyFix(scanId, remediationCommands) {
    const response = await fetch(`${API_BASE_URL}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scan_id: scanId,
        remediation_commands: remediationCommands,
      }),
      cache: 'no-cache',
    });

    return handleResponse(response);
  },

  async getExplanation(scanId, ruleId, hostname) {
    const response = await fetch(
      `${API_BASE_URL}/assistant/explain/${scanId}/${ruleId}/${hostname}`,
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

  async downloadFixedConfigs(scanId) {
    const response = await fetch(`${API_BASE_URL}/download-fixed`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId }),
      cache: 'no-cache',
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: response.statusText }));
      throw new Error(error.detail || `API error: ${response.status}`);
    }

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
