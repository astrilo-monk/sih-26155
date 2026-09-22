// @vitest-environment jsdom
import { StrictMode } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';

vi.mock('../api/client', () => ({
  apiClient: {
    getRemediationPlan: vi.fn(),
    getRemediation: vi.fn(),
    downloadFixedConfigs: vi.fn(),
    getProvisionalResults: vi.fn(),
    getReviewQueue: vi.fn(),
    remediationCandidate: vi.fn(),
    downloadCandidateConfig: vi.fn(),
  },
}));

import { apiClient } from '../api/client';
import { useAudit } from '../lib/useAudit';
import Fix from './Fix';

const store = new Map();
vi.stubGlobal('localStorage', {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
  clear: () => store.clear(),
});

const result = (control_id, extra = {}) => ({
  config_index: 0, control_id, title: `${control_id} title`, question: `Is ${control_id} satisfied?`, category: 'management',
  severity: 'high', status: 'fail', assurance: 'parser', proposed_status: null, device_hostname: 'R1', vendor: 'cisco_ios',
  scope: null, reason: `${control_id} fails`, evidence: { line_numbers: [3], lines: ['ip ssh version 1'], scope_path: [] }, ...extra,
});

const SCAN = {
  scan_id: 'scan-1', timestamp: '2026-09-14T08:00:00', posture: 0, coverage: 100,
  devices: [{ hostname: 'R1', vendor: 'cisco_ios' }],
  vendor_identification: [{ config_index: 0, detected_vendor: 'cisco_ios', status: 'confirmed' }],
  results: [result('MGMT-007', { severity: 'critical' }), result('LOG-001'), result('BOUNDARY-001', { severity: 'critical' }), result('MGMT-005')],
  findings: [{ rule_id: 'BOUNDARY-001', config_index: 0, description: 'Any-to-any permit', security_impact: 'Everything is reachable',
    recommendation: "Replace it with explicit rules, e.g. 'permit tcp 10.0.0.0 0.0.0.255 any eq 443'" }],
  frameworks: [],
};

const SUMMARY = { posture: 0, coverage: 100, posture_bounds: [0, 0], critical_unassessed: [], vendor_status: 'confirmed', parse_coverage: 1, uncovered_lines: 0 };
const item = (rule_id, status, extra = {}) => ({
  rule_id, title: `${rule_id} title`, device_hostname: 'R1', vendor: 'cisco_ios', config_index: 0, status,
  reason: `${status} reason`, explanation: '', warnings: [], scopes: [], evidence: { line_numbers: [], lines: [], scope_path: [] },
  required_inputs: [], missing_inputs: [], diff: '', checks: [], before: null, after: null, fixed_config: null, ...extra,
});
const FIXED_SSH = item('MGMT-007', 'fixed', {
  reason: 'MGMT-007 now passes: SSH is restricted to version 2', diff: '@@ -3,1 +3,1 @@\n-ip ssh version 1\n+ip ssh version 2',
  checks: [{ name: 'target', passed: true, detail: 'MGMT-007 now passes' }],
});
const plan = (remediations, extra = {}) => ({
  scan_id: 'scan-1',
  inputs: [{ name: 'syslog_server', label: 'Syslog server', help: 'IPv4 address of the remote log collector' }],
  devices: [{
    config_index: 0, device_hostname: 'R1', vendor: 'cisco_ios', vendor_status: 'confirmed', fixed_controls: ['MGMT-007'], checks: [],
    before: SUMMARY, after: { ...SUMMARY, posture: 40 }, fixed_config: 'hostname R1', remediations, ...extra,
  }],
});
const PLAN = plan([
  FIXED_SSH,
  item('LOG-001', 'needs_input', { missing_inputs: ['syslog_server'], reason: 'Provide Syslog server to generate this change' }),
  item('BOUNDARY-001', 'manual_review', { reason: 'Replacing an any-to-any permit needs the intended sources, destinations and services; a deterministic rewrite could cut production traffic' }),
  item('MGMT-005', 'no_recipe'),
]);

function Harness({ scan = SCAN }) {
  const audit = useAudit(scan, 1);
  return <Fix scan={scan} audit={audit} labels={['R1']} onOpen={() => {}} onTeach={() => {}} />;
}

beforeEach(() => {
  store.clear();
  apiClient.getProvisionalResults.mockResolvedValue({ items: [] });
  apiClient.getReviewQueue.mockResolvedValue({ items: [] });
  apiClient.downloadFixedConfigs.mockResolvedValue(undefined);
  apiClient.downloadCandidateConfig.mockResolvedValue(undefined);
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('sorts every problem into can fix, needs input and manual action, and explains manual fixes with backend commands', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(PLAN);
  const writeText = vi.fn().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
  const { container } = render(<Harness />);

  expect(await screen.findByText('We can fix 1 problem automatically')).toBeTruthy();
  expect(within(screen.getByRole('region', { name: /Can fix automatically/ })).getAllByRole('listitem')).toHaveLength(1);
  expect(within(screen.getByRole('region', { name: /Needs your input/ })).getAllByRole('listitem')).toHaveLength(1);
  const manual = screen.getByRole('region', { name: /Needs manual action/ });
  expect(within(manual).getAllByRole('listitem')).toHaveLength(2);
  // a decisive failure needing a person's change is manual action, never review
  expect(container.textContent).not.toMatch(/needs review|requires review/i);

  const [boundary, password] = within(manual).getAllByRole('button', { name: 'How to fix' });
  fireEvent.click(boundary);
  expect(screen.getByText(/We won’t change this automatically/)).toBeTruthy();
  expect(screen.getByText(/a deterministic rewrite could cut production traffic/)).toBeTruthy();
  expect(screen.getByText('permit tcp 10.0.0.0 0.0.0.255 any eq 443')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Copy commands' }));
  await waitFor(() => expect(writeText).toHaveBeenCalledWith('permit tcp 10.0.0.0 0.0.0.255 any eq 443'));
  expect(await screen.findByText('Copied')).toBeTruthy();

  fireEvent.click(password);
  expect(screen.getByText('We can’t fix this automatically.')).toBeTruthy();
  expect(screen.getByText(/no proven automatic fix for this setting/)).toBeTruthy();
});

it('fix all shows the verified before and after, what remains, and downloads the plan it verified', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(PLAN);
  render(<Harness />);
  fireEvent.click(await screen.findByRole('button', { name: 'Fix all 1' }));

  expect(screen.getByText('Fixes verified')).toBeTruthy();
  expect(screen.getByText('1 problem fixed · 3 remaining')).toBeTruthy();
  expect(screen.getByText('40')).toBeTruthy();
  expect(within(screen.getByRole('region', { name: /^Fixed/ })).getByText('MGMT-007 title')).toBeTruthy();

  fireEvent.click(screen.getAllByRole('button', { name: 'Download corrected configuration' })[0]);
  await waitFor(() => expect(apiClient.downloadFixedConfigs).toHaveBeenCalledWith('scan-1', {}));
  expect(await screen.findByText('Downloaded your corrected configuration.')).toBeTruthy();
});

it('asks only for the value a fix needs, then shows the verified fix and downloads with that value', async () => {
  const withSyslog = plan([
    FIXED_SSH,
    item('LOG-001', 'fixed', { reason: 'LOG-001 now passes: Logs are forwarded to 10.20.0.5', diff: '@@ -9,0 +9,1 @@\n+logging host 10.20.0.5' }),
    item('BOUNDARY-001', 'manual_review'),
    item('MGMT-005', 'no_recipe'),
  ], { fixed_controls: ['MGMT-007', 'LOG-001'] });
  apiClient.getRemediationPlan
    .mockResolvedValueOnce(PLAN)
    .mockResolvedValueOnce(plan([FIXED_SSH, item('LOG-001', 'needs_input', { missing_inputs: ['syslog_server'], reason: 'Syslog server must be an IPv4 address' })]))
    .mockResolvedValueOnce(withSyslog);
  render(<Harness />);

  expect(await screen.findByText('We know the problem. We need your syslog server to fix it.')).toBeTruthy();
  const generate = screen.getByRole('button', { name: 'Generate fix' });
  expect(generate.disabled).toBe(true);

  fireEvent.change(screen.getByLabelText('Syslog server'), { target: { value: 'not-an-ip' } });
  fireEvent.click(generate);
  expect(await screen.findByText('Syslog server must be an IPv4 address')).toBeTruthy();

  fireEvent.change(screen.getByLabelText('Syslog server'), { target: { value: '10.20.0.5' } });
  fireEvent.click(screen.getByRole('button', { name: 'Generate fix' }));
  await waitFor(() => expect(apiClient.getRemediationPlan).toHaveBeenLastCalledWith('scan-1', { syslog_server: '10.20.0.5' }));
  expect(await screen.findByText('Fix verified')).toBeTruthy();
  expect(screen.getByText('Logs are forwarded to 10.20.0.5')).toBeTruthy();

  // answering a question keeps the one-click path for the automatic fixes that are still waiting
  expect(screen.getByText('1 problem fixed · 3 remaining')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Fix the other 1 automatically' }));
  expect(screen.getByText('2 problems fixed · 2 remaining')).toBeTruthy();
  expect(screen.queryByRole('button', { name: /Fix the other/ })).toBeNull();

  fireEvent.click(screen.getAllByRole('button', { name: 'Download corrected configuration' })[0]);
  await waitFor(() => expect(apiClient.downloadFixedConfigs).toHaveBeenCalledWith('scan-1', { syslog_server: '10.20.0.5' }));
});

it('fixes one problem through the backend and only calls it fixed when the rescan verified it', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(PLAN);
  apiClient.getRemediation.mockResolvedValueOnce({ ...FIXED_SSH, status: 'verification_failed', reason: 'MGMT-006 got worse' });
  render(<Harness />);
  const can = await screen.findByRole('region', { name: /Can fix automatically/ });
  // automatic fixes start closed ("Fix all" covers them); opening one shows its own action
  expect(within(can).queryByRole('button', { name: 'Fix this' })).toBeNull();
  fireEvent.click(within(can).getByRole('button', { name: 'How to fix' }));

  fireEvent.click(within(can).getByRole('button', { name: 'Fix this' }));
  await waitFor(() => expect(apiClient.getRemediation).toHaveBeenCalledWith('scan-1', 'MGMT-007', 'R1', 0, {}));
  expect(await screen.findByText(/the rescan didn’t confirm it -so it is not in your download/)).toBeTruthy();
  expect(screen.queryByText('Fixes verified')).toBeNull();
});

it('prepares the plan once per scan state, even when StrictMode runs effects twice', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(PLAN);
  render(<StrictMode><Harness /></StrictMode>);
  expect(await screen.findByText('We can fix 1 problem automatically')).toBeTruthy();
  expect(apiClient.getRemediationPlan).toHaveBeenCalledTimes(1);
});

it('says a clean configuration is already clean', async () => {
  const clean = { ...SCAN, results: [result('MGMT-007', { status: 'pass' })], findings: [] };
  apiClient.getRemediationPlan.mockResolvedValue(plan([], { fixed_controls: [], fixed_config: null }));
  render(<Harness scan={clean} />);
  expect(await screen.findByText('Your configuration is already clean.')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Download corrected configuration' })).toBeNull();
});

// ── Candidate remediation for an unconfirmed vendor ──────────────────────────────────────────────────────────

const UNKNOWN_SCAN = {
  ...SCAN,
  devices: [{ hostname: 'JUNIPER-EDGE-01', vendor: 'unknown' }],
  vendor_identification: [{ config_index: 0, detected_vendor: 'unknown', status: 'unknown' }],
  results: [result('MGMT-001', {
    assurance: 'confirmed', severity: 'critical', device_hostname: 'JUNIPER-EDGE-01', vendor: 'unknown',
    title: 'Insecure Management Protocol (Telnet) Enabled', question: 'Is cleartext Telnet disabled for remote management?',
    evidence: { line_numbers: [32], lines: ['        telnet;'], scope_path: ['system', 'services'] },
  })],
  findings: [{ rule_id: 'MGMT-001', config_index: 0, description: 'Telnet is enabled',
    security_impact: 'Credentials cross the network in cleartext',
    recommendation: 'Disable Telnet and use SSH for remote management.' }],
};

const unknownPlan = (candidates = []) => ({
  scan_id: 'scan-1', inputs: [],
  devices: [{ config_index: 0, device_hostname: 'JUNIPER-EDGE-01', vendor: 'unknown', vendor_status: 'unknown',
    fixed_controls: [], checks: [], before: null, after: null, fixed_config: null, candidates,
    remediations: [item('MGMT-001', 'vendor_unverified', { device_hostname: 'JUNIPER-EDGE-01', vendor: 'unknown' })] }],
});

const candidate = (status, extra = {}) => ({
  config_index: 0, rule_id: 'MGMT-001', title: 'Insecure Management Protocol (Telnet) Enabled',
  device_hostname: 'JUNIPER-EDGE-01', vendor: 'unknown', vendor_status: 'unknown', source: 'ai', status,
  command: 'delete system services telnet;', reason: `${status} reason`,
  explanation: 'Removes the Telnet service from the system services hierarchy.', confidence: 'medium',
  assumptions: ['a curly-brace hierarchical CLI'], evidence: { line_numbers: [32], lines: ['        telnet;'], scope_path: [] },
  control_status_before: 'fail', control_status_after: null, checks: [], diff: '', download_available: false,
  created_at: '2026-09-18T13:00:00', confirmed_at: null, ...extra,
});

it('offers a candidate fix instead of a dead end when the vendor is not confirmed', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(unknownPlan());
  render(<Harness scan={UNKNOWN_SCAN} />);

  // the problem is its own group, open, and says what is missing -never "can't fix"
  expect(await screen.findByRole('region', { name: /Needs administrator input/ })).toBeTruthy();
  expect(screen.getAllByText('Needs administrator input').length).toBeGreaterThan(0);
  expect(screen.getByText(/vendor and command syntax are not confirmed/)).toBeTruthy();
  expect(screen.getByText('Disable Telnet and use SSH for remote management.')).toBeTruthy();
  // one status for the finding, and only one: no candidate yet means it is still waiting on a person
  const finding = within(screen.getByRole('region', { name: /Needs administrator input/ }));
  expect(finding.getAllByText((_, el) => el?.className === 'status-word')).toHaveLength(1);
  expect(finding.getByText('Needs input')).toBeTruthy();
  expect(screen.queryByText('We can’t fix this automatically.')).toBeNull();
  // the page footnote explains the same thing, and never claims a device was touched
  expect(screen.getByText(/never writes vendor commands for R1|never writes vendor commands for JUNIPER-EDGE-01/)).toBeTruthy();
  expect(screen.getByText(/It never connects to the device\./)).toBeTruthy();
});

it('derives the fix from the configuration itself: no AI, already verified, still needs confirming', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(unknownPlan());
  apiClient.remediationCandidate.mockResolvedValueOnce(candidate('verified', {
    source: 'derived', command: 'delete system services telnet',
    explanation: 'NetAuditAI derived this from the configuration itself: the lines this finding cites, removed from the block they sit in.',
    confidence: '', assumptions: [], control_status_after: 'not_configured', download_available: true,
    diff: '--- before\n+++ after\n@@ -30,3 +30,2 @@\n-        telnet;',
    checks: [{ name: 'target', passed: true, detail: 'MGMT-001 fail → not_configured on the edited copy' },
             { name: 'no_regression', passed: true, detail: 'No other control got worse' },
             { name: 'generic_path', passed: true, detail: 'The edited copy is still read by generic analysis' }],
    reason: 'Verified against the uploaded configuration: MGMT-001 fail → not_configured on a copy of it. This does not establish that the command is safe to run on the physical device.',
  }));
  render(<Harness scan={UNKNOWN_SCAN} />);

  fireEvent.click(await screen.findByRole('button', { name: 'Fix it for me' }));
  await waitFor(() => expect(apiClient.remediationCandidate).toHaveBeenCalledWith(
    'derive', 'scan-1', 'MGMT-001', 'JUNIPER-EDGE-01', 0, {}));

  // it is labelled as NetAuditAI's own reading of the file, not an AI guess and not a typed command
  expect(await screen.findByText('Derived from your configuration')).toBeTruthy();
  expect(screen.queryByText('AI-generated candidate')).toBeNull();
  expect(screen.getByText('delete system services telnet')).toBeTruthy();
  // verified when it arrives, and still nothing applied anywhere
  expect(screen.getByText(/does not establish that the command is safe to run on the physical device/)).toBeTruthy();
  expect(screen.getByRole('button', { name: /Confirm/ })).toBeTruthy();
});

it('says a removal cannot resolve a check that needs a setting', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(unknownPlan());
  apiClient.remediationCandidate.mockRejectedValueOnce(Object.assign(
    new Error('NetAuditAI cannot derive a change for MGMT-001 from this configuration: it can only remove settings the finding cites, and this one needs a setting to be added or changed in syntax it does not know.'),
    { status: 422 }));
  render(<Harness scan={UNKNOWN_SCAN} />);

  fireEvent.click(await screen.findByRole('button', { name: 'Fix it for me' }));
  expect(await screen.findByText(/it can only remove settings the finding cites/)).toBeTruthy();
  // the other two ways to get a command are still offered
  expect(screen.getByRole('button', { name: 'Ask AI for a command' })).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Enter command manually' })).toBeTruthy();
});

it('generates an AI candidate, labels it unverified, verifies it and confirms it', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(unknownPlan());
  apiClient.remediationCandidate
    .mockResolvedValueOnce(candidate('draft', { reason: 'Accepted for review. NetAuditAI has not checked it against this configuration yet.' }))
    .mockResolvedValueOnce(candidate('verified', {
      reason: 'Verified against the uploaded configuration: MGMT-001 fail → not_configured on a copy of it. This does not establish that the command is safe to run on the physical device.',
      control_status_after: 'not_configured', diff: '@@ -30,3 +30,2 @@\n-        telnet;\n         ftp;',
      checks: [{ name: 'target', passed: true, detail: 'MGMT-001 fail → not_configured on the edited copy' },
        { name: 'no_regression', passed: true, detail: 'No other control got worse' }],
    }))
    .mockResolvedValueOnce(candidate('confirmed', {
      reason: 'Confirmed by an administrator. It was verified against the uploaded configuration; NetAuditAI has not connected to the device and has not changed it.',
      control_status_after: 'not_configured', confirmed_at: '2026-09-18T13:05:00',
    }));
  render(<Harness scan={UNKNOWN_SCAN} />);

  fireEvent.click(await screen.findByRole('button', { name: 'Ask AI for a command' }));
  await waitFor(() => expect(apiClient.remediationCandidate)
    .toHaveBeenCalledWith('generate', 'scan-1', 'MGMT-001', 'JUNIPER-EDGE-01', 0, {}));
  expect(await screen.findByText('AI-generated candidate')).toBeTruthy();
  expect(screen.getByText('Not checked yet')).toBeTruthy();
  expect(screen.getByText('delete system services telnet;')).toBeTruthy();
  expect(screen.getByText(/Removes the Telnet service/)).toBeTruthy();
  // assumptions are collapsed by default so they never compete with the command
  expect(screen.queryByText(/Assumes: a curly-brace hierarchical CLI/)).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Assumptions (1)' }));
  expect(screen.getByText(/Assumes: a curly-brace hierarchical CLI/)).toBeTruthy();
  // an unchecked candidate can never be confirmed straight away
  expect(screen.queryByRole('button', { name: 'Confirm' })).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: 'Verify candidate' }));
  expect(await screen.findByText('Verified against this configuration')).toBeTruthy();
  expect(screen.getByText(/fail → not_configured on a copy of your configuration/)).toBeTruthy();
  expect(screen.getByText(/does not establish that the command is safe to run on the physical device/)).toBeTruthy();
  // the rescan checks and the simulated diff are detail behind a disclosure, not a second wall of status
  fireEvent.click(screen.getByRole('button', { name: 'Show what it changes' }));
  expect(screen.getByText('This problem is gone')).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
  expect(await screen.findByText('Confirmed by you')).toBeTruthy();
  expect(screen.getAllByText(/has not connected to the device/).length).toBeGreaterThan(0);
  // the scan itself never moves: the problem is still a problem until the device is changed and rescanned
  expect(screen.queryByText('Fixes verified')).toBeNull();
  expect(screen.getByRole('region', { name: /Needs administrator input/ })).toBeTruthy();
});

it('sends a manually entered command as a candidate and shows a rejected one as rejected', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(unknownPlan());
  apiClient.remediationCandidate
    .mockResolvedValueOnce(candidate('draft', { source: 'manual', confidence: '', explanation: '', assumptions: [] }))
    .mockResolvedValueOnce(candidate('rejected', { source: 'manual', confidence: '', explanation: '', assumptions: [],
      reason: 'The candidate did not hold up: MGMT-001 still fails on the edited copy',
      control_status_after: 'fail',
      checks: [{ name: 'target', passed: false, detail: 'MGMT-001 still fails on the edited copy' }] }));
  render(<Harness scan={UNKNOWN_SCAN} />);

  fireEvent.click(await screen.findByRole('button', { name: 'Enter command manually' }));
  const box = screen.getByLabelText('Command for this device');
  fireEvent.change(box, { target: { value: 'delete system services telnet;' } });
  fireEvent.click(screen.getByRole('button', { name: 'Use this command' }));
  await waitFor(() => expect(apiClient.remediationCandidate)
    .toHaveBeenCalledWith('propose', 'scan-1', 'MGMT-001', 'JUNIPER-EDGE-01', 0, { command: 'delete system services telnet;' }));
  expect(await screen.findByText('Command you entered')).toBeTruthy();

  fireEvent.click(screen.getByRole('button', { name: 'Verify candidate' }));
  expect(await screen.findByText('Rejected')).toBeTruthy();
  expect(screen.getAllByText(/still fails on the edited copy/).length).toBeGreaterThan(0);
  expect(screen.queryByRole('button', { name: 'Confirm' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Propose another command' })).toBeTruthy();
});

it('explains when no candidate can be generated and keeps the manual path open', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(unknownPlan());
  apiClient.remediationCandidate.mockRejectedValueOnce(
    new Error('AI is not configured, so no candidate can be generated. Enter the command for this device yourself.'));
  render(<Harness scan={UNKNOWN_SCAN} />);

  fireEvent.click(await screen.findByRole('button', { name: 'Ask AI for a command' }));
  expect(await screen.findByText(/AI is not configured/)).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Enter command manually' })).toBeTruthy();
});

it('keeps a candidate the backend already holds when the plan is reloaded', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(unknownPlan([candidate('unverified', {
    reason: 'Accepted for review, but it could not be verified automatically.' })]));
  render(<Harness scan={UNKNOWN_SCAN} />);
  expect(await screen.findByText('Not verified')).toBeTruthy();
  expect(screen.getByText(/could not be verified automatically/)).toBeTruthy();
  // a human may still accept a command NetAuditAI could not check, knowingly
  expect(screen.getByRole('button', { name: 'Confirm anyway' })).toBeTruthy();
});

it('offers the verified corrected copy of a confirmed candidate, and never a device configuration', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(unknownPlan([candidate('confirmed', {
    control_status_after: 'not_configured', confirmed_at: '2026-09-18T13:05:00', download_available: true,
    checks: [{ name: 'target', passed: true, detail: 'MGMT-001 fail → not_configured on the edited copy' }] })]));
  render(<Harness scan={UNKNOWN_SCAN} />);

  // the copy is per candidate; the page-wide "corrected configuration" is still only for a confirmed vendor
  const copy = await screen.findByRole('button', { name: 'Download verified corrected copy' });
  expect(screen.getByRole('button', { name: 'Download corrected configuration' }).disabled).toBe(true);
  expect(screen.getByText(/No corrected device configuration for an unconfirmed vendor/)).toBeTruthy();
  expect(screen.queryByText('Nothing to download yet: no fix has been verified.')).toBeNull();
  // the warning says what the file is and what it is not
  expect(screen.getByText('Verified against a copy of your uploaded configuration. This file has not been applied to a device.')).toBeTruthy();
  expect(screen.getByText(/never writes vendor commands for R1|never writes vendor commands for JUNIPER-EDGE-01/)).toBeTruthy();

  fireEvent.click(copy);
  await waitFor(() => expect(apiClient.downloadCandidateConfig)
    .toHaveBeenCalledWith('scan-1', 'MGMT-001', 'JUNIPER-EDGE-01', 0));
  expect(apiClient.downloadFixedConfigs).not.toHaveBeenCalled();
});

it('offers the verified copy as soon as a candidate verifies, and not a moment earlier', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(unknownPlan());
  apiClient.remediationCandidate
    .mockResolvedValueOnce(candidate('draft', { source: 'manual' }))
    .mockResolvedValueOnce(candidate('verified', { source: 'manual', control_status_after: 'not_configured',
      download_available: true,
      checks: [{ name: 'target', passed: true, detail: 'MGMT-001 fail → not_configured on the edited copy' }] }));
  render(<Harness scan={UNKNOWN_SCAN} />);

  // no candidate at all
  expect(await screen.findByRole('button', { name: 'Enter command manually' })).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Download verified corrected copy' })).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: 'Enter command manually' }));
  fireEvent.change(screen.getByLabelText('Command for this device'), { target: { value: 'delete system services telnet;' } });
  fireEvent.click(screen.getByRole('button', { name: 'Use this command' }));
  // a draft has been checked against nothing: there is no copy to hand out
  expect(await screen.findByText('Not checked yet')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Download verified corrected copy' })).toBeNull();

  fireEvent.click(screen.getByRole('button', { name: 'Verify candidate' }));
  expect(await screen.findByRole('button', { name: 'Download verified corrected copy' })).toBeTruthy();
});

it('offers no copy for a candidate the checks rejected', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(unknownPlan([candidate('rejected', {
    reason: 'The candidate did not hold up: MGMT-001 still fails on the edited copy', control_status_after: 'fail',
    checks: [{ name: 'target', passed: false, detail: 'MGMT-001 still fails on the edited copy' }] })]));
  render(<Harness scan={UNKNOWN_SCAN} />);

  expect(await screen.findByText('Rejected')).toBeTruthy();
  expect(screen.queryByRole('button', { name: 'Download verified corrected copy' })).toBeNull();
  expect(screen.getByText('Nothing to download yet: no fix has been verified.')).toBeTruthy();
});

it('still says nothing has been verified when no candidate has been checked', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(unknownPlan([candidate('draft')]));
  render(<Harness scan={UNKNOWN_SCAN} />);

  expect(await screen.findByText('Nothing to download yet: no fix has been verified.')).toBeTruthy();
  expect(screen.queryByText(/No corrected file for an unconfirmed vendor/)).toBeNull();
});
