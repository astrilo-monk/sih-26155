// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import Fleet from './Fleet';

const fail = (config_index, control_id, severity, assurance = 'parser') => ({
  config_index, control_id, title: `${control_id} title`, severity, status: 'fail', assurance,
});
const SCAN = {
  devices: [{ hostname: 'a', posture: 40, coverage: 90 }, { hostname: 'b', posture: 75, coverage: 60 }],
  results: [
    fail(0, 'MGMT-001', 'critical'), fail(0, 'MGMT-001', 'critical'), fail(0, 'LOG-001', 'high'),
    fail(1, 'MGMT-001', 'critical'), fail(1, 'MGMT-003', 'high', 'heuristic'),
  ],
  attack_paths: [{ config_index: 0 }],
};

afterEach(cleanup);

it('stays out of the way for a single device', () => {
  const { container } = render(<Fleet scan={{ ...SCAN, devices: SCAN.devices.slice(0, 1) }} labels={['a']} />);
  expect(container.firstChild).toBeNull();
});

it('shows each device’s score and decided problems, and what fails most often across the fleet', () => {
  render(<Fleet scan={SCAN} labels={['a', 'b']} />);
  screen.getByRole('heading', { name: 'Across 2 devices' });
  screen.getByText((_, el) => el?.textContent === '40 · 90% checked');
  // one control failing twice on a device counts once; a suspected (heuristic) FAIL is not counted
  screen.getByText((_, el) => el?.textContent === '2 · 1 critical · 1 high · 1 attack path');
  screen.getByText((_, el) => el?.textContent === '1 · 1 critical');
  screen.getByText((_, el) => el?.textContent === 'MGMT-001 MGMT-001 title · 2 of 2 devices');
});

it('lists problems only visible across devices, citing each device and line', () => {
  render(<Fleet scan={{ ...SCAN, fleet_findings: [{ check: 'shared-snmp-community', severity: 'high',
    title: 'The same SNMP community string is used on 2 devices', why: 'The value is not shown.',
    devices: [{ config_index: 0, lines: [53], value: null }, { config_index: 1, lines: [16], value: null }] }] }} labels={['a', 'b']} />);
  screen.getByRole('heading', { name: 'Problems only visible across devices' });
  screen.getByText('The same SNMP community string is used on 2 devices');
  screen.getByText((_, el) => el?.tagName === 'LI' && el.textContent === 'b · line 16');
});
