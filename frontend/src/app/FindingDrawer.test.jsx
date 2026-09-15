// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../api/client', () => ({
  apiClient: {
    getRemediationPlan: vi.fn(),
    getRemediation: vi.fn(),
    getProvisionalResults: vi.fn(),
    getReviewQueue: vi.fn(),
  },
}));

import { apiClient } from '../api/client';
import { checkItems } from '../lib/domain';
import { useAudit } from '../lib/useAudit';
import FindingDrawer from './FindingDrawer';

const result = (extra) => ({
  config_index: 1, control_id: 'MGMT-001', title: 'Telnet enabled', question: 'Is Telnet disabled?', category: 'management',
  severity: 'critical', status: 'fail', assurance: 'parser', proposed_status: null, device_hostname: 'BRANCH-FGT-02', vendor: 'fortinet',
  scope: 'interface wan1', reason: 'Telnet is allowed on wan1',
  evidence: { line_numbers: [21], lines: ['        set allowaccess ping https ssh http telnet'], scope_path: [] }, ...extra,
});

// two uploads share one hostname: config_index is the identity
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
    result({ config_index: 0, control_id: 'MGMT-003', title: 'Unrestricted management', status: 'fail', assurance: 'heuristic' }),
  ],
  findings: [{
    rule_id: 'MGMT-001', title: 'Telnet enabled', severity: 'critical', config_index: 1, device_hostname: 'BRANCH-FGT-02',
    description: 'Telnet is allowed on interface wan1.', security_impact: 'Credentials are sniffable',
    recommendation: "Remove 'telnet' from allowaccess", compliance: [{ framework: 'NIST_800_53', control_id: 'AC-17(2)', description: 'Protection' }],
  }],
};
const LABELS = ['BRANCH-FGT-02 (#1)', 'BRANCH-FGT-02 (#2)'];
const FIXED = {
  rule_id: 'MGMT-001', title: 'Telnet enabled', device_hostname: 'BRANCH-FGT-02', vendor: 'fortinet', config_index: 1, status: 'fixed',
  reason: 'MGMT-001 now passes: Telnet is not allowed for remote management', explanation: 'Removes telnet', warnings: [], scopes: ['interface wan1'],
  evidence: { line_numbers: [21], lines: [], scope_path: [] }, missing_inputs: [], required_inputs: [],
  diff: '@@ -21,1 +21,1 @@\n-        set allowaccess ping https ssh http telnet\n+        set allowaccess ping https ssh',
  checks: [{ name: 'target', passed: true, detail: 'MGMT-001 now passes' }], before: null, after: null,
};

function Harness({ controlId, onClose = () => {}, onTeach = () => {} }) {
  const audit = useAudit(SCAN, 1);
  const item = checkItems(SCAN, audit.plan).find((i) => i.controlId === controlId);
  return <FindingDrawer item={item} scan={SCAN} audit={audit} labels={LABELS} onClose={onClose} onTeach={onTeach} />;
}

beforeEach(() => {
  apiClient.getRemediationPlan.mockResolvedValue({ scan_id: 'scan-1', inputs: [], devices: [{ config_index: 1, remediations: [FIXED], fixed_controls: ['MGMT-001'] }] });
  apiClient.getProvisionalResults.mockResolvedValue({ items: [] });
  apiClient.getReviewQueue.mockResolvedValue({ items: [] });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('leads with what is wrong, why it matters and what to do; evidence and internals open on request', async () => {
  const onClose = vi.fn();
  render(<Harness controlId="MGMT-001" onClose={onClose} />);

  expect(screen.getByRole('dialog', { name: 'Telnet enabled' })).toBeTruthy();
  expect(screen.getByText('Telnet is allowed on interface wan1.')).toBeTruthy();
  expect(screen.getByText('Credentials are sniffable')).toBeTruthy();
  expect(await screen.findByText('NetAuditAI can fix this safely.')).toBeTruthy();
  expect(screen.queryByText('set allowaccess ping https ssh http telnet', { exact: false })).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: 'Show evidence' }));
  expect(screen.getByText('set allowaccess ping https ssh http telnet', { exact: false })).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Show compliance' }));
  expect(screen.getByText('NIST SP 800-53 AC-17(2)')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Show detection method' }));
  expect(screen.getByText('Read directly by a dedicated parser')).toBeTruthy();

  fireEvent.keyDown(document, { key: 'Escape' });
  expect(onClose).toHaveBeenCalled();
});

it("fixes the finding's own upload, not the first configuration sharing its hostname", async () => {
  apiClient.getRemediation.mockResolvedValue(FIXED);
  render(<Harness controlId="MGMT-001" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Fix this' }));
  await waitFor(() => expect(apiClient.getRemediation).toHaveBeenCalledWith('scan-1', 'MGMT-001', 'BRANCH-FGT-02', 1, {}));
  expect(await screen.findByText('Fix verified')).toBeTruthy();
  expect(screen.getByText('Telnet is not allowed for remote management')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Show the change' }));
  expect(screen.getByText('set allowaccess ping https ssh', { selector: '.diff-row.add code' })).toBeTruthy();
});

it('a reading that needs review offers teaching, never a fix', async () => {
  const onTeach = vi.fn();
  render(<Harness controlId="MGMT-003" onTeach={onTeach} />);
  expect(screen.getAllByText('Needs review').length).toBeGreaterThan(0);
  expect(screen.queryByRole('button', { name: 'Fix this' })).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Teach NetAuditAI' }));
  expect(onTeach).toHaveBeenCalled();
});

it('shows absence as Not configured, never as a pass', () => {
  render(<Harness controlId="LOG-001" />);
  expect(screen.getAllByText('Not configured').length).toBeGreaterThan(0);
  expect(screen.getByText(/not counted as a pass/)).toBeTruthy();
  expect(screen.queryByText('Passed')).toBeNull();
});
