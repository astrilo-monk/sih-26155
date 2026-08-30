const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api';

async function handleResponse(response) {
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || `API error: ${response.status}`);
  }
  return response.json();
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
    });

    return handleResponse(response);
  },

  async getScan(scanId) {
    const response = await fetch(`${API_BASE_URL}/scan/${scanId}`);
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
    });

    return handleResponse(response);
  },

  async getExplanation(scanId, ruleId, hostname) {
    const response = await fetch(
      `${API_BASE_URL}/assistant/explain/${scanId}/${ruleId}/${hostname}`
    );
    return handleResponse(response);
  },

  async getSummary(scanId) {
    const response = await fetch(`${API_BASE_URL}/assistant/summary/${scanId}`);
    return handleResponse(response);
  },

  async chat(scanId, message) {
    const response = await fetch(`${API_BASE_URL}/assistant/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId, message }),
    });
    return handleResponse(response);
  },
};
