// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { ProgressStrip } from './AppShell';

afterEach(cleanup);

const scan = {
  scan_id: 's1', devices: [{ hostname: 'R1' }], findings: [], assessed_count: 12, unresolved_count: 11,
  results: [{ config_index: 0, control_id: 'MGMT-001', status: 'fail', assurance: 'parser', severity: 'critical' }],
};
const plan = { devices: [{ config_index: 0, remediations: [{ rule_id: 'MGMT-001', config_index: 0, status: 'fixed' }] }] };

it('says where the audit stands and offers the one next step', () => {
  const go = vi.fn();
  render(<ProgressStrip scan={scan} audit={{ plan, applied: new Set(), queue: null }} view="teach" go={go} />);
  expect(screen.getByText('12 of 23 checks decided · 1 ready to fix')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Next: Fix them' }));
  expect(go).toHaveBeenCalledWith('fix');
});

it('does not offer the page you are already on', () => {
  render(<ProgressStrip scan={scan} audit={{ plan, applied: new Set(), queue: null }} view="fix" go={() => {}} />);
  expect(screen.queryByRole('button')).toBeNull();
});
