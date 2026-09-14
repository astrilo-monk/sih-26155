// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import DeviceInfo, { deviceRows } from './DeviceInfo';

afterEach(cleanup);

const finding = (config_index, severity, assurance) => ({ rule_id: 'MGMT-001', severity, assurance, config_index, device_hostname: 'x' });

// paloalto.cfg + unknown.cfg (both generic) + two FortiGates sharing one hostname
const SCAN = {
  devices: [
    { hostname: 'unknown', vendor: 'unknown' },
    { hostname: 'unknown', vendor: 'unknown' },
    { hostname: 'BRANCH-FGT-02', vendor: 'fortinet' },
    { hostname: 'BRANCH-FGT-02', vendor: 'fortinet' },
  ],
  vendor_identification: [
    { config_index: 0, status: 'unknown' }, { config_index: 1, status: 'unknown' },
    { config_index: 2, status: 'confirmed' }, { config_index: 3, status: 'confirmed' },
  ],
  findings: [
    finding(0, 'critical', 'heuristic'), finding(0, 'high', 'heuristic'), finding(1, 'critical', 'ai_verified'),
    finding(3, 'high', 'parser'),
  ],
  results: [
    { config_index: 0, status: 'fail', assurance: 'heuristic' },
    { config_index: 2, status: 'pass', assurance: 'parser' },
    { config_index: 3, status: 'fail', assurance: 'parser' },
  ],
};

it('keeps devices with the same hostname apart and never derives risk from suspected findings', () => {
  const rows = deviceRows(SCAN);
  expect(rows.map((r) => [r.decisive, r.suspected, r.risk])).toEqual([
    [0, 2, 'NOT ASSESSED'],
    [0, 1, 'NOT ASSESSED'],
    [0, 0, 'LOW'],
    [1, 0, 'HIGH'],
  ]);
  expect(rows.map((r) => r.analysis)).toEqual(['Generic analysis', 'Generic analysis', 'Dedicated parser', 'Dedicated parser']);
});

it('renders no hardcoded device status and no CRITICAL from provisional findings', () => {
  const { container } = render(<DeviceInfo scanResult={SCAN} />);
  expect(container.textContent).not.toContain('Active');
  expect(container.textContent).not.toContain('CRITICAL');
  expect(screen.getAllByText('NOT ASSESSED')).toHaveLength(2);
});
