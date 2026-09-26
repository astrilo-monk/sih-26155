// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

vi.mock('../api/client', () => ({ apiClient: { getCatalog: vi.fn() } }));

import { apiClient } from '../api/client';
import Rules from './Rules';

afterEach(() => { cleanup(); vi.clearAllMocks(); });

it('lists every check with what it reads and the requirements it answers, filterable by framework', async () => {
  apiClient.getCatalog.mockResolvedValue({
    controls: [
      { control_id: 'MGMT-001', title: 'Telnet', question: 'Is Telnet off?', severity: 'critical', reads: ['mgmt.remote_access.protocol_enabled'],
        requirements: [{ framework: 'NIST_800_53', version: 'Rev. 5', requirement_id: 'AC-17(2)', title: 'x', vendor: null },
          { framework: 'CIS', version: 'IOS XE', requirement_id: '1.2.4', title: 'y', vendor: 'cisco_ios' }] },
      { control_id: 'LOG-001', title: 'Syslog', question: 'Logs forwarded?', severity: 'high', reads: ['log.remote.destination'],
        requirements: [{ framework: 'NIST_800_53', version: 'Rev. 5', requirement_id: 'AU-9(2)', title: 'z', vendor: null }] },
    ],
    requirements: { CIS: 1, NIST_800_53: 2 },
    requirement_total: 3,
  });
  render(<Rules />);
  await screen.findByText('3 framework requirements');
  screen.getByText('CIS Benchmarks 1.2.4 (cisco_ios)');
  fireEvent.change(screen.getByRole('combobox'), { target: { value: 'CIS' } });
  expect(screen.queryByText('Syslog')).toBeNull();
  screen.getByText('Telnet');
});
