// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import Frameworks from './Frameworks';

const control = (extra) => ({
  control_id: 'MGMT-001', title: 'Telnet', config_index: 0, device_hostname: 'R1', status: 'fail', assurance: 'parser',
  proposed_status: null, provisional: false, decisive: true, outcome: 'fail', reason: 'Telnet is allowed',
  evidence: { line_numbers: [87], lines: [' transport input telnet ssh'], scope_path: [] }, ...extra,
});

const FRAMEWORKS = [
  {
    framework: 'NIST_800_53', version: 'SP 800-53 Rev. 5 (5.2.0)', coverage: 50, counts: { fail: 1, unknown: 1 },
    requirements: [
      { requirement_id: 'AC-17(2)', title: 'Protection of Confidentiality', status: 'fail', provisional: false, controls: [control()] },
      { requirement_id: 'SC-45', title: 'System Time Synchronization', status: 'unknown', provisional: true,
        controls: [control({ control_id: 'LOG-002', status: 'unknown', assurance: 'ai_verified', proposed_status: 'pass', provisional: true, decisive: false, outcome: 'undecided', evidence: { line_numbers: [], lines: [], scope_path: [] } })] },
    ],
  },
  { framework: 'CIS', version: 'Cisco IOS XE 17.x Benchmark v2.2.1 (Level 1)', coverage: 100, counts: { pass: 1 },
    requirements: [{ requirement_id: '1.2.2', title: "Set 'transport input ssh'", status: 'pass', provisional: false, controls: [control({ status: 'pass', outcome: 'pass' })] }] },
];

afterEach(cleanup);

it('shows requirement statuses, readings that need review, unmapped frameworks and switches views', () => {
  render(<Frameworks frameworks={FRAMEWORKS} />);
  expect(screen.getByText('50% of requirements decided')).toBeTruthy();
  expect(screen.getByText('Needs review')).toBeTruthy();
  expect(screen.getByText(/not a compliance certification/)).toBeTruthy();
  expect(screen.getByText(/ISO\/IEC 27001, CIS Controls v8 and DISA STIG are not mapped/)).toBeTruthy();

  fireEvent.click(screen.getByText('SC-45'));
  expect(screen.getByText('Needs review -not counted')).toBeTruthy();
  fireEvent.click(screen.getByText('AC-17(2)'));
  expect(screen.getByText('Decided from evidence')).toBeTruthy();
  expect(screen.getByText('transport input telnet ssh', { exact: false })).toBeTruthy();

  const groups = [...screen.getByLabelText('Framework').querySelectorAll('optgroup')].map((g) => g.label);
  expect(groups).toEqual(['NIST SP 800-53', 'CIS']);
  expect(screen.getByRole('option', { name: 'Cisco IOS XE 17.x Benchmark v2.2.1 (Level 1) · 1 requirement' })).toBeTruthy();

  fireEvent.change(screen.getByLabelText('Framework'), { target: { value: '1' } });
  expect(screen.getByText('1.2.2')).toBeTruthy();
  expect(screen.getByText('100% of requirements decided')).toBeTruthy();
});
