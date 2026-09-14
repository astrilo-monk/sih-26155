// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../api/client', () => ({ apiClient: { getRemediation: vi.fn() } }));

import { apiClient } from '../api/client';
import Findings, { buildRows } from './Findings';

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const result = (extra) => ({
  config_index: 1, control_id: 'MGMT-001', title: 'Telnet enabled', question: 'Is Telnet disabled?', kind: 'k', category: 'management',
  severity: 'critical', status: 'fail', assurance: 'parser', proposed_status: null, device_hostname: 'BRANCH-FGT-02', vendor: 'fortinet',
  scope: 'interface wan1', reason: 'Telnet is allowed on wan1',
  evidence: { line_numbers: [21], lines: ['        set allowaccess ping https ssh http telnet'], scope_path: [] }, ...extra,
});

const SCAN = {
  scan_id: 'scan-1',
  devices: [{ hostname: 'BRANCH-FGT-02', vendor: 'fortinet' }, { hostname: 'BRANCH-FGT-02', vendor: 'fortinet' }],
  vendor_identification: [
    { config_index: 0, detected_vendor: 'fortinet', status: 'confirmed' },
    { config_index: 1, detected_vendor: 'fortinet', status: 'confirmed' },
  ],
  results: [
    result(),
    result({ config_index: 0, control_id: 'LOG-001', title: 'No syslog', question: 'Are logs forwarded?', status: 'not_configured', assurance: null, scope: null, evidence: { line_numbers: [], lines: [], scope_path: [] } }),
  ],
  findings: [{
    rule_id: 'MGMT-001', title: 'Telnet enabled', severity: 'critical', config_index: 1, device_hostname: 'BRANCH-FGT-02', vendor: 'fortinet',
    line_numbers: [21], evidence_lines: ['  21:         set allowaccess ping https ssh http telnet'], security_impact: 'Credentials are sniffable',
    recommendation: "Remove 'telnet' from allowaccess", compliance: [{ framework: 'NIST_800_53', control_id: 'AC-17(2)', description: 'Protection' }],
    assurance: 'parser', description: 'd', category: 'management',
  }],
};

it("remediates the finding's own upload, not the first config sharing its hostname, and shows the verified diff", async () => {
  apiClient.getRemediation.mockResolvedValue({
    rule_id: 'MGMT-001', title: 'Telnet enabled', device_hostname: 'BRANCH-FGT-02', vendor: 'fortinet', config_index: 1, status: 'fixed',
    reason: 'MGMT-001 now passes', explanation: 'Removes telnet', warnings: [], scopes: ['interface wan1'],
    evidence: { line_numbers: [21], lines: ['set allowaccess ping https ssh http telnet'], scope_path: [] },
    diff: '@@ -21,1 +21,1 @@\n-        set allowaccess ping https ssh http telnet\n+        set allowaccess ping https ssh',
    checks: [{ name: 'target', passed: true, detail: 'MGMT-001 now passes' }], required_inputs: [], missing_inputs: [],
    before: null, after: null,
  });
  render(<Findings scan={SCAN} />);

  expect(screen.getByText('BRANCH-FGT-02 (#2)', { selector: '.kv dd' })).toBeTruthy();
  expect(screen.getByText('set allowaccess ping https ssh http telnet', { exact: false })).toBeTruthy();
  expect(screen.getByText('Credentials are sniffable')).toBeTruthy();
  expect(screen.getByText('Parser evidence')).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Generate deterministic fix' }));
  await waitFor(() => expect(apiClient.getRemediation).toHaveBeenCalledWith('scan-1', 'MGMT-001', 'BRANCH-FGT-02', 1));
  expect(await screen.findByText('Verified')).toBeTruthy();
  expect(screen.getByText('set allowaccess ping https ssh', { selector: '.diff-row.add code' })).toBeTruthy();
});

it('never offers remediation for a provisional finding and says it is not counted', () => {
  const scan = {
    ...SCAN,
    vendor_identification: [{ config_index: 0, status: 'unknown' }, { config_index: 1, status: 'unknown' }],
    results: [result({ assurance: 'heuristic' })],
    findings: [{ ...SCAN.findings[0], assurance: 'heuristic' }],
  };
  render(<Findings scan={scan} />);
  expect(screen.getByText('Human review required — not counted')).toBeTruthy();
  expect(screen.getByText('Suspected · not counted')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Generate deterministic fix' })).toBeNull();
  expect(screen.getByText(/Provisional findings never trigger remediation/)).toBeTruthy();
});

it('shows absence as Not configured, never as a pass', () => {
  render(<Findings scan={SCAN} />);
  fireEvent.click(screen.getByRole('button', { name: /Undecided/ }));
  expect(screen.getByText(/never as a pass/)).toBeTruthy();
  expect(screen.getAllByText('Not configured').length).toBeGreaterThan(0);
});

it('pairs each failing result with the finding that cites the same lines', () => {
  const scan = {
    ...SCAN,
    results: [result({ evidence: { line_numbers: [17], lines: ['a'], scope_path: [] } }), result({ evidence: { line_numbers: [18], lines: ['b'], scope_path: [] } })],
    findings: [{ ...SCAN.findings[0], line_numbers: [18], recommendation: 'eighteen' }, { ...SCAN.findings[0], line_numbers: [17], recommendation: 'seventeen' }],
  };
  expect(buildRows(scan).map((r) => r.finding.recommendation)).toEqual(['seventeen', 'eighteen']);
});
