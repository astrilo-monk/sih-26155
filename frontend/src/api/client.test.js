// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { apiClient, UNREACHABLE } from './client';

afterEach(() => vi.unstubAllGlobals());

it('says the server cannot be reached instead of "Failed to fetch"', async () => {
  vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')));
  await expect(apiClient.getScan('s1')).rejects.toMatchObject({ message: UNREACHABLE, status: 0 });
});

it('names the field and what to enter when a value is refused', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
    detail: { message: 'Please check what you entered', errors: { 'NTP key': 'use 8-32 letters, e.g. NtpKey-2026' } },
  }), { status: 422 })));
  await expect(apiClient.getRemediationPlan('s1', {})).rejects.toMatchObject({
    message: 'Please check what you entered. NTP key: use 8-32 letters, e.g. NtpKey-2026.', status: 422,
  });
});

it('saves every device’s baseline model as one JSON file', async () => {
  const fetchMock = vi.fn((url) => Promise.resolve(new Response(JSON.stringify({ device: { hostname: url.slice(-1) } }))));
  vi.stubGlobal('fetch', fetchMock);
  let saved = null;
  vi.stubGlobal('URL', { createObjectURL: (blob) => { saved = blob; return 'blob:x'; }, revokeObjectURL: () => {} });
  await apiClient.downloadBaseline('abcdef123456', 2);
  expect(fetchMock.mock.calls.map(([url]) => url.split('/api')[1])).toEqual([
    '/scan/abcdef123456/baseline?config_index=0', '/scan/abcdef123456/baseline?config_index=1',
  ]);
  const text = await new Promise((done) => { const r = new FileReader(); r.onload = () => done(r.result); r.readAsText(saved); });
  expect(JSON.parse(text)).toEqual({ devices: [{ device: { hostname: '0' } }, { device: { hostname: '1' } }] });
});
