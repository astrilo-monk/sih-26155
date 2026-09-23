// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';

vi.mock('./api/client', () => ({
  apiClient: {
    isScanHeld: vi.fn().mockResolvedValue(true),
    getScan: vi.fn(),
    listLearnedMappings: vi.fn().mockResolvedValue([]),
  },
}));

import { apiClient } from './api/client';
import App from './App';

const store = new Map();
vi.stubGlobal('localStorage', {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
  clear: () => store.clear(),
});

const go = (hash) => {
  window.location.hash = hash;
  window.dispatchEvent(new HashChangeEvent('hashchange'));
};

beforeEach(() => {
  store.clear();
  window.location.hash = '';
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

it('opens on the public homepage, states support honestly, and Try now enters the application', async () => {
  const { container } = render(<App />);
  expect(screen.getByRole('heading', { level: 1 }).textContent).toMatch(/and why\./);
  expect(screen.getAllByRole('link', { name: 'Try now' })[0].getAttribute('href')).toBe('#/app');
  expect(container.textContent).toContain('PCI DSS and CIS Controls v8 are not mapped today.');
  expect(container.textContent).not.toMatch(/(works with|supports) every vendor|100% accurate|fully autonomous|understands every/i);

  go('#/app');
  expect(await screen.findByText(/Upload a network configuration, or collect one from the devices/)).toBeTruthy();
  expect(screen.getByRole('button', { name: 'Start scan' }).disabled).toBe(true);
});

it('reports an audit the backend no longer holds as expired instead of showing stale results', async () => {
  apiClient.getScan.mockRejectedValue(Object.assign(new Error('Scan not found'), { status: 404 }));
  go('#/app/scan/gone-1/findings');
  render(<App />);
  expect(await screen.findByText('This scan is no longer available.')).toBeTruthy();
  expect(apiClient.getScan).toHaveBeenCalledWith('gone-1');
});

it('shows what NetAuditAI has learned, with an honest empty state (old recognizer links still work)', async () => {
  go('#/app/recognizers');
  render(<App />);
  expect(await screen.findByText('NetAuditAI hasn’t learned anything yet')).toBeTruthy();
  expect(apiClient.listLearnedMappings).toHaveBeenCalledWith(true);
});
