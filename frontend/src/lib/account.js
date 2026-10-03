import { useSyncExternalStore } from 'react';

/**
 * Who this browser is to the backend (backend app/auth.py). When the deployment has accounts on, a signed-in
 * request carries the Supabase access token and reads only that account's taught knowledge; a guest carries a
 * random id kept in this browser, and what it teaches stays on the server only until the server restarts.
 * With accounts off (a local install) nothing is sent and everyone shares one store, as before.
 *
 * The Supabase URL and public anon key come from the backend (/api/account/config), so the two can never be
 * configured differently.
 */

const GUEST_KEY = 'netauditai.guestId';
let state = { enabled: false, loaded: false, user: null };
let token = null;
let supabase = null;
let ready = Promise.resolve();
const listeners = new Set();

function set(next) {
  state = { ...state, ...next };
  listeners.forEach((fn) => fn());
}

function guestId() {
  try {
    let id = localStorage.getItem(GUEST_KEY);
    if (!id) localStorage.setItem(GUEST_KEY, (id = crypto.randomUUID()));
    return id;
  } catch {
    // storage blocked: a guest for as long as this page is open
    return (guestId.fallback ||= crypto.randomUUID());
  }
}

/** Headers every API request carries: none until the backend says accounts are on. */
export function identityHeaders() {
  if (!state.enabled) return {};
  return token ? { Authorization: `Bearer ${token}` } : { 'X-Guest-Id': guestId() };
}

/** Resolves once the first request may go out with the right identity. */
export const accountReady = () => ready;

/** Called once by the app shell. Requests wait for it, so a scan never goes out as a stray guest. */
export function initAccount(apiBase) {
  if (state.loaded || supabase) return ready;
  ready = (async () => {
    try {
      const response = await globalThis.fetch(`${apiBase}/account/config`, { cache: 'no-cache' });
      const config = response.ok ? await response.json() : { accounts: false };
      if (config.accounts) {
        const { createClient } = await import('@supabase/supabase-js');
        supabase = createClient(config.supabase_url, config.supabase_anon_key);
        const { data } = await supabase.auth.getSession();
        token = data.session?.access_token ?? null;
        supabase.auth.onAuthStateChange((_event, session) => {
          token = session?.access_token ?? null;
          set({ user: session?.user ?? null });
        });
        set({ enabled: true, user: data.session?.user ?? null });
      }
    } catch {
      // backend unreachable: requests report that themselves
    } finally {
      set({ loaded: true });
    }
  })();
  return ready;
}

export async function signIn(email, password) {
  const { error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) throw error;
}

/** Returns true when Supabase wants the address confirmed before the first sign-in. */
export async function signUp(email, password) {
  const { data, error } = await supabase.auth.signUp({
    email, password, options: { emailRedirectTo: window.location.origin + window.location.pathname },
  });
  if (error) throw error;
  return !data.session;
}

export async function signOut() {
  await supabase.auth.signOut();
}

export function useAccount() {
  return useSyncExternalStore((fn) => { listeners.add(fn); return () => listeners.delete(fn); }, () => state);
}
