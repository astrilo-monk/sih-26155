// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

vi.mock('../api/client', () => ({ apiClient: { getDrift: vi.fn() } }));

import { apiClient } from '../api/client';
import Drift from './Drift';

const c = (control_id) => ({ control_id, title: `${control_id} title`, severity: 'high' });

afterEach(() => { cleanup(); vi.clearAllMocks(); });

it('shows what was fixed, what broke and what lost its evidence since the last scan of the device', async () => {
  apiClient.getDrift.mockResolvedValue({ devices: [{
    config_index: 0, hostname: 'r1', previous_scan_id: 'a', previous_at: '2026-09-01T10:00:00',
    posture: [20, 55], risk: ['critical', 'high'], fixed: [c('MGMT-001')], new_problems: [c('LOG-001')],
    no_longer_decided: [c('AUTH-001')], paths_closed: ['Remote takeover'], paths_opened: [],
  }] });
  render(<Drift scanId="s2" labels={['edge-rtr']} />);
  await screen.findByRole('heading', { name: 'Since the last audit' });
  screen.getByText((_, el) => el?.tagName === 'P' && el.textContent.startsWith('Score 20 → 55 · risk critical → high · attack paths closed: Remote takeover'));
  screen.getByRole('heading', { name: 'Fixed (1)' });
  screen.getByRole('heading', { name: 'New problems (1)' });
  screen.getByRole('heading', { name: 'No longer decided (evidence missing, not fixed) (1)' });
  expect(apiClient.getDrift).toHaveBeenCalledWith('s2');
});

it('shows nothing for a device seen for the first time', async () => {
  apiClient.getDrift.mockResolvedValue({ devices: [] });
  const { container } = render(<Drift scanId="s1" labels={['r1']} />);
  await Promise.resolve();
  expect(container.firstChild).toBeNull();
});
