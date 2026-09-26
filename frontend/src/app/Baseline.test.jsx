// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

vi.mock('../api/client', () => ({ apiClient: { getBaseline: vi.fn() } }));

import { apiClient } from '../api/client';
import Baseline from './Baseline';

const model = (vendor, value, line, text) => ({
  device: { vendor },
  settings: [{ field: 'mgmt.ssh.version', subject: null, value, unit: null, assurance: vendor === 'cisco_ios' ? 'parser' : 'confirmed',
    lines: [{ number: line, text }] }],
  read_by: { 'mgmt.ssh.version': ['MGMT-007'], 'log.remote.destination': ['LOG-001'] },
});

afterEach(() => { cleanup(); vi.clearAllMocks(); });

it('loads every device on request and shows the same fields side by side, each value tied to its line', async () => {
  apiClient.getBaseline.mockImplementation((_, i) => Promise.resolve(
    i === 0 ? model('cisco_ios', 1, 27, 'ip ssh version 1') : model('unknown', 2, 6, 'protocol-version v2;')));
  render(<Baseline scanId="s1" labels={['edge-rtr', 'srx']} />);
  expect(apiClient.getBaseline).not.toHaveBeenCalled();

  fireEvent.click(screen.getByRole('button', { name: 'Compare the devices field by field' }));
  const cisco = await screen.findByTitle('line 27: ip ssh version 1');
  expect(cisco.textContent).toContain('1');
  expect(screen.getByTitle('line 6: protocol-version v2;').textContent).toContain('2');
  expect(screen.getAllByText('not stated')).toHaveLength(2); // syslog: neither file states it
  expect(apiClient.getBaseline.mock.calls.map((c) => c[1])).toEqual([0, 1]);
});

it('spells structured values out instead of printing an object', async () => {
  const { shown } = await import('./Baseline');
  expect(shown({ encryption: 'des', dh_group: 1 })).toBe('encryption des, dh_group 1');
  expect(shown([true, 'not_set'])).toBe('yes, not set');
});
