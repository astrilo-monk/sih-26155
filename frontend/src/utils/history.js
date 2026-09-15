// Scan history kept in this browser. Only a summary is stored — never findings, evidence or configuration
// lines (they can hold secrets). Opening an entry fetches the scan from the backend, which keeps scans in
// memory until it restarts: an entry the backend no longer holds is marked expired, never reopened.
// TODO: once auth lands, scope per-user, e.g. `netauditai_scan_history_${userId}`.
export function getHistoryStorageKey() {
  return "netauditai_scan_history";
}

import { problems } from "../lib/domain";

function summarize(scanResult) {
  return {
    id: scanResult.scan_id,
    timestamp: new Date().toISOString(),
    hostnames: (scanResult.devices || []).map((d) => d.hostname),
    vendors: (scanResult.devices || []).map((d) => d.vendor),
    posture: scanResult.posture ?? null,
    coverage: scanResult.coverage ?? 0,
    // the same count the results page shows: decisive failures, one per control per configuration
    problemsCount: problems(scanResult).length,
  };
}

export function saveScanToHistory(scanResult) {
  try {
    const existing = getScanHistory().filter((e) => e.id !== scanResult.scan_id);
    existing.unshift(summarize(scanResult));
    localStorage.setItem(getHistoryStorageKey(), JSON.stringify(existing.slice(0, 20)));
  } catch (err) {
    console.warn("Failed to save scan to history:", err);
  }
}

export function getScanHistory() {
  try {
    const stored = JSON.parse(localStorage.getItem(getHistoryStorageKey()) || "[]");
    // Entries from older versions carried the full scan result (evidence lines): drop it from storage
    if (stored.some((e) => e.fullResult)) {
      const cleaned = stored.map((e) => (e.fullResult ? { ...summarize(e.fullResult), id: e.id, timestamp: e.timestamp } : e));
      localStorage.setItem(getHistoryStorageKey(), JSON.stringify(cleaned));
      return cleaned;
    }
    return stored;
  } catch {
    return [];
  }
}

export function markScansExpired(ids) {
  try {
    const expired = new Set(ids);
    const updated = getScanHistory().map((e) => (expired.has(e.id) ? { ...e, expired: true } : e));
    localStorage.setItem(getHistoryStorageKey(), JSON.stringify(updated));
  } catch (err) {
    console.warn("Failed to update scan history:", err);
  }
}

// A verified fixed configuration was downloaded for this scan (a flag only — no configuration content)
export function markRemediated(id) {
  try {
    const updated = getScanHistory().map((e) => (e.id === id ? { ...e, remediated: true } : e));
    localStorage.setItem(getHistoryStorageKey(), JSON.stringify(updated));
  } catch (err) {
    console.warn("Failed to update scan history:", err);
  }
}

export function clearScanHistory() {
  localStorage.removeItem(getHistoryStorageKey());
}
