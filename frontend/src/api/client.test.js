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
