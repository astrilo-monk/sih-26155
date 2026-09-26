// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import FirstRunTips from './FirstRunTips';

const store = new Map();
beforeEach(() => {
  store.clear();
  vi.stubGlobal('localStorage', { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)) });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('shows three steps once, and not again after "Got it"', () => {
  render(<FirstRunTips />);
  expect(screen.getByText('New here? Three steps')).toBeTruthy();
  fireEvent.click(screen.getByRole('button', { name: 'Got it' }));
  expect(screen.queryByText('New here? Three steps')).toBeNull();
  cleanup();
  render(<FirstRunTips />);
  expect(screen.queryByText('New here? Three steps')).toBeNull();
});

it('still works when the browser blocks storage', () => {
  vi.stubGlobal('localStorage', { getItem: () => { throw new Error('blocked'); }, setItem: () => { throw new Error('blocked'); } });
  render(<FirstRunTips />);
  fireEvent.click(screen.getByRole('button', { name: 'Got it' }));
  expect(screen.queryByText('New here? Three steps')).toBeNull();
});
