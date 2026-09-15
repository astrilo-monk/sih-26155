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
  expect(await screen.findByText(/the rescan didn’t confirm it — so it is not in your download/)).toBeTruthy();
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

it('never shows vendor commands for an unconfirmed vendor', async () => {
  const unknown = {
    ...SCAN,
    vendor_identification: [{ config_index: 0, detected_vendor: 'unknown', status: 'unknown' }],
    results: [result('BOUNDARY-001', { assurance: 'confirmed' })],
  };
  apiClient.getRemediationPlan.mockResolvedValue({
    scan_id: 'scan-1', inputs: [],
    devices: [{ config_index: 0, device_hostname: 'R1', vendor: 'unknown', vendor_status: 'unknown', fixed_controls: [], checks: [], before: null, after: null, fixed_config: null,
      remediations: [item('BOUNDARY-001', 'vendor_unverified')] }],
  });
  render(<Harness scan={unknown} />);
  fireEvent.click(await screen.findByRole('button', { name: 'How to fix' }));
  expect(screen.getByText(/couldn’t confirm which vendor this device is/)).toBeTruthy();
  expect(screen.queryByText(/Commands for/)).toBeNull();
  expect(screen.queryByText('permit tcp 10.0.0.0 0.0.0.255 any eq 443')).toBeNull();
  expect(screen.getByText(/never generates vendor commands for R1/)).toBeTruthy();
});
