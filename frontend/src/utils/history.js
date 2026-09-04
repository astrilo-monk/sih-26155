// TODO: once auth lands, scope per-user, e.g. `netauditai_scan_history_${userId}`.
// All read/write below goes through this function.
export function getHistoryStorageKey() {
  return "netauditai_scan_history";
}

export function saveScanToHistory(scanResult) {
  try {
    const key = getHistoryStorageKey();
    const existing = JSON.parse(localStorage.getItem(key) || "[]");

    const entry = {
      id: scanResult.scan_id,
      timestamp: new Date().toISOString(),
      hostname:
        scanResult.device?.hostname || scanResult.devices?.[0]?.hostname,
      vendor: scanResult.vendor,
      score: scanResult.score,
      findingsCount: scanResult.findings?.length ?? 0,
      fullResult: scanResult,
    };

    existing.unshift(entry);
    const capped = existing.slice(0, 20);
    localStorage.setItem(key, JSON.stringify(capped));
  } catch (err) {
    console.warn("Failed to save scan to history:", err);
  }
}

export function getScanHistory() {
  try {
    const key = getHistoryStorageKey();
    return JSON.parse(localStorage.getItem(key) || "[]");
  } catch {
    return [];
  }
}

export function clearScanHistory() {
  localStorage.removeItem(getHistoryStorageKey());
}
