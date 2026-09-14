// @vitest-environment jsdom
import { StrictMode } from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../api/client', () => ({
  apiClient: {
    getRemediationPlan: vi.fn(),
    downloadFixedConfigs: vi.fn(),
  },
}));

import { apiClient } from '../api/client';
import Remediation from './Remediation';

const store = new Map();
vi.stubGlobal('localStorage', {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
  clear: () => store.clear(),
});

const SUMMARY = { posture: 0, coverage: 100, posture_bounds: [0, 0], critical_unassessed: [], vendor_status: 'confirmed', parse_coverage: 1, uncovered_lines: 0 };
const item = (rule_id, status, extra = {}) => ({
  rule_id, title: `${rule_id} title`, device_hostname: 'R1', vendor: 'cisco_ios', config_index: 0, status,
  reason: `${status} reason`, warnings: [], scopes: [], evidence: { line_numbers: [], lines: [], scope_path: [] },
  required_inputs: [], missing_inputs: [], diff: '', checks: [], before: null, after: null, fixed_config: null, ...extra,
});

const PLAN = {
  scan_id: 'scan-1',
  inputs: [{ name: 'syslog_server', label: 'Syslog server', help: 'IPv4 address' }],
  devices: [
    {
      config_index: 0, device_hostname: 'R1', vendor: 'cisco_ios', vendor_status: 'confirmed',
      fixed_controls: ['MGMT-007'], checks: [], before: SUMMARY, after: { ...SUMMARY, posture: 40 }, fixed_config: 'hostname R1',
      remediations: [
        item('MGMT-007', 'fixed', { diff: '@@ -3,1 +3,1 @@\n-ip ssh version 1\n+ip ssh version 2', checks: [{ name: 'target', passed: true, detail: 'MGMT-007 now passes' }] }),
        item('LOG-001', 'needs_input', { missing_inputs: ['syslog_server'] }),
        item('BOUNDARY-001', 'manual_review'),
        item('MGMT-005', 'no_recipe'),
      ],
    },
    {
      config_index: 1, device_hostname: 'unknown', vendor: 'unknown', vendor_status: 'unknown', fixed_controls: [], checks: [],
      before: null, after: null, fixed_config: null,
      remediations: [item('MGMT-001', 'vendor_unverified', { config_index: 1, device_hostname: 'unknown' })],
    },
  ],
};

const SCAN = { scan_id: 'scan-1', devices: [{ hostname: 'R1' }, { hostname: 'unknown' }] };
const button = () => screen.getByText('Download verified configuration').closest('button');

beforeEach(() => store.clear());

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('separates verified, needs input, requires review, no recipe and blocked; inputs regenerate the plan', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(PLAN);
  render(<Remediation scan={SCAN} />);

  expect(await screen.findByLabelText('Verified: 1')).toBeTruthy();
  for (const label of ['Needs input: 1', 'Requires review: 1', 'No recipe: 1', 'Blocked: 1']) {
    expect(screen.getByLabelText(label)).toBeTruthy();
  }
  expect(apiClient.getRemediationPlan).toHaveBeenCalledWith('scan-1', {});

  fireEvent.click(screen.getByText('MGMT-007 title'));
  expect(screen.getByText('ip ssh version 2')).toBeTruthy();
  expect(screen.getByText(/MGMT-007 now passes/)).toBeTruthy();

  fireEvent.change(screen.getByLabelText('Syslog server'), { target: { value: '10.20.0.5' } });
  fireEvent.click(screen.getByText('Generate with these values'));
  await waitFor(() => expect(apiClient.getRemediationPlan).toHaveBeenLastCalledWith('scan-1', { syslog_server: '10.20.0.5' }));
  // the regenerated plan must be on screen before its configuration can be downloaded
  await waitFor(() => expect(button().disabled).toBe(false));

  fireEvent.click(button());
  await waitFor(() => expect(apiClient.downloadFixedConfigs).toHaveBeenCalledWith('scan-1', { syslog_server: '10.20.0.5' }));
});

it('downloads only the reviewed plan: changed values are never silently used', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(PLAN);
  render(<Remediation scan={SCAN} />);

  fireEvent.change(await screen.findByLabelText('Syslog server'), { target: { value: '10.0.0.1' } });
  fireEvent.click(screen.getByText('Generate with these values'));
  await waitFor(() => expect(button().disabled).toBe(false));

  fireEvent.change(screen.getByLabelText('Syslog server'), { target: { value: '10.0.0.2' } });
  expect(button().disabled).toBe(true);
  expect(screen.getByText(/Values changed since this plan was generated/)).toBeTruthy();
  fireEvent.click(button());
  expect(apiClient.downloadFixedConfigs).not.toHaveBeenCalled();

  fireEvent.click(screen.getByText('Generate with these values'));
  await waitFor(() => expect(apiClient.getRemediationPlan).toHaveBeenLastCalledWith('scan-1', { syslog_server: '10.0.0.2' }));
  await waitFor(() => expect(button().disabled).toBe(false));
  fireEvent.click(button());
  await waitFor(() => expect(apiClient.downloadFixedConfigs).toHaveBeenCalledWith('scan-1', { syslog_server: '10.0.0.2' }));
  expect(apiClient.downloadFixedConfigs).toHaveBeenCalledTimes(1);
  expect(await screen.findByText(/Downloaded the configuration for the plan shown above/)).toBeTruthy();
});

it('generates the plan once per scan state, even when StrictMode runs effects twice', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(PLAN);
  render(<StrictMode><Remediation scan={SCAN} planKey="scan-1:1" /></StrictMode>);
  expect(await screen.findByLabelText('Verified: 1')).toBeTruthy();
  expect(apiClient.getRemediationPlan).toHaveBeenCalledTimes(1);
});

it('regenerates the plan with its own inputs when the scan is re-evaluated', async () => {
  apiClient.getRemediationPlan.mockResolvedValue(PLAN);
  const { rerender } = render(<Remediation scan={SCAN} planKey="scan-1:1" />);
  fireEvent.change(await screen.findByLabelText('Syslog server'), { target: { value: '10.0.0.9' } });
  fireEvent.click(screen.getByText('Generate with these values'));
  await waitFor(() => expect(apiClient.getRemediationPlan).toHaveBeenCalledTimes(2));

  rerender(<Remediation scan={SCAN} planKey="scan-1:2" />);
  await waitFor(() => expect(apiClient.getRemediationPlan).toHaveBeenCalledTimes(3));
  expect(apiClient.getRemediationPlan).toHaveBeenLastCalledWith('scan-1', { syslog_server: '10.0.0.9' });
});

it('disables download when nothing was verified', async () => {
  apiClient.getRemediationPlan.mockResolvedValue({ ...PLAN, devices: [PLAN.devices[1]] });
  render(<Remediation scan={SCAN} />);
  expect((await screen.findByText('Download verified configuration')).closest('button').disabled).toBe(true);
  expect(screen.getByText('No verified fix is available.')).toBeTruthy();
});
