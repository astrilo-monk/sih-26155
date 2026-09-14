// @vitest-environment jsdom
import { beforeEach, expect, it, vi } from 'vitest';
import { getHistoryStorageKey, getScanHistory, markRemediated, saveScanToHistory } from './history';

// Some Node / jsdom combinations expose a partial localStorage: use a plain in-memory one
const store = new Map();
vi.stubGlobal('localStorage', {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
  clear: () => store.clear(),
});

const SCAN = {
  scan_id: 'scan-1', posture: 42, coverage: 90, score: 12,
  devices: [{ hostname: 'R1', vendor: 'cisco_ios' }],
  findings: [
    { rule_id: 'MGMT-005', assurance: 'parser', evidence_lines: ['  15: enable password 7 0822455D0A16'] },
    { rule_id: 'MGMT-001', assurance: 'heuristic', evidence_lines: ['  70: remote-console protocol telnet'] },
  ],
  results: [{ evidence: { lines: ['username admin password 0 FakeSecret1'] } }],
};

beforeEach(() => localStorage.clear());

it('stores a summary only, never evidence or configuration lines', () => {
  saveScanToHistory(SCAN);
  const raw = localStorage.getItem(getHistoryStorageKey());
  expect(raw).not.toContain('0822455D0A16');
  expect(raw).not.toContain('FakeSecret1');
  expect(getScanHistory()).toEqual([expect.objectContaining({
    id: 'scan-1', hostnames: ['R1'], posture: 42, coverage: 90, findingsCount: 1,
  })]);
});

it('records a verified download as a flag only', () => {
  saveScanToHistory(SCAN);
  markRemediated('scan-1');
  expect(getScanHistory()[0].remediated).toBe(true);
  expect(localStorage.getItem(getHistoryStorageKey())).not.toContain('FakeSecret1');
});

it('strips full results saved by older versions', () => {
  localStorage.setItem(getHistoryStorageKey(), JSON.stringify([{ id: 'scan-1', timestamp: 't', fullResult: SCAN }]));
  expect(getScanHistory()[0].posture).toBe(42);
  expect(localStorage.getItem(getHistoryStorageKey())).not.toContain('FakeSecret1');
});
