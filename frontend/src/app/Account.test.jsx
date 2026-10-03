// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';

// A Supabase project whose session the test controls
let session = null;
vi.mock('@supabase/supabase-js', () => ({
  createClient: () => ({
    auth: {
      getSession: async () => ({ data: { session } }),
      onAuthStateChange: () => ({ data: { subscription: { unsubscribe() {} } } }),
    },
  }),
}));

afterEach(() => { vi.unstubAllGlobals(); vi.resetModules(); session = null; });

async function boot(config) {
  const calls = [];
  const stored = new Map();
  vi.stubGlobal('localStorage', { getItem: (k) => stored.get(k) ?? null, setItem: (k, v) => stored.set(k, v) });
  vi.stubGlobal('fetch', vi.fn(async (url, options) => {
    calls.push({ url, headers: options?.headers || {} });
    return new Response(JSON.stringify(url.endsWith('/account/config') ? config : []));
  }));
  const { apiClient } = await import('../api/client');
  await apiClient.startAccount();
  await apiClient.listLearnedMappings(true);
  return calls.at(-1).headers;
}

it('sends nothing extra when the deployment has no accounts', async () => {
  expect(await boot({ accounts: false })).toEqual({});
});

it('speaks as this browser’s guest when signed out, and warns that teaching is not kept', async () => {
  const headers = await boot({ accounts: true, supabase_url: 'https://x.supabase.co', supabase_anon_key: 'anon' });
  expect(headers['X-Guest-Id']).toMatch(/^[0-9a-f-]{36}$/);
  expect(headers.Authorization).toBeUndefined();
  // the same guest on the next visit
  expect(localStorage.getItem('netauditai.guestId')).toBe(headers['X-Guest-Id']);

  const { GuestNotice } = await import('./Account');
  await act(async () => { render(<GuestNotice />); });
  expect(screen.getByText('What you teach as a guest is not saved.')).toBeTruthy();
});

it('sends the access token once signed in, and no guest id', async () => {
  session = { access_token: 'jwt-123', user: { id: 'u1', email: 'a@b.c' } };
  const headers = await boot({ accounts: true, supabase_url: 'https://x.supabase.co', supabase_anon_key: 'anon' });
  expect(headers).toEqual({ Authorization: 'Bearer jwt-123' });

  const { GuestNotice } = await import('./Account');
  const { container } = render(<GuestNotice />);
  expect(container.textContent).toBe('');
});
