// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';

vi.mock('../api/client', () => ({ apiClient: { isScanHeld: vi.fn() } }));

import { apiClient } from '../api/client';
import { getHistoryStorageKey } from '../utils/history';
import HistoryView from './HistoryView';

const store = new Map();
vi.stubGlobal('localStorage', {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
  clear: () => store.clear(),
});

const entry = (id, hostname) => ({
  id, timestamp: '2026-09-14T08:00:00Z', hostnames: [hostname], vendors: ['cisco_ios'], posture: 40, coverage: 80, findingsCount: 2,
});

beforeEach(() => {
  store.clear();
  localStorage.setItem(getHistoryStorageKey(), JSON.stringify([entry('live', 'R1'), entry('gone', 'R2')]));
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('marks scans the backend no longer holds as expired and never reopens them', async () => {
  apiClient.isScanHeld.mockImplementation(async (id) => id === 'live');
  const onSelect = vi.fn().mockResolvedValue(undefined);
  const onExpired = vi.fn();
  render(<HistoryView onSelectHistoryEntry={onSelect} onScansExpired={onExpired} />);

  expect(await screen.findByText('Expired')).toBeTruthy();
  expect(onExpired).toHaveBeenCalledWith(['gone']);
  expect(JSON.parse(localStorage.getItem(getHistoryStorageKey())).find((e) => e.id === 'gone').expired).toBe(true);

  fireEvent.click(screen.getByText('R2'));
  expect(onSelect).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText('R1'));
  await waitFor(() => expect(onSelect).toHaveBeenCalledWith('live'));
});

it('does not claim scans are available when the backend cannot be reached', async () => {
  apiClient.isScanHeld.mockRejectedValue(new Error('Failed to fetch'));
  render(<HistoryView onSelectHistoryEntry={vi.fn()} />);
  expect(await screen.findByText(/backend could not be reached/)).toBeTruthy();
  expect(screen.queryByText('Available')).toBeNull();
});
