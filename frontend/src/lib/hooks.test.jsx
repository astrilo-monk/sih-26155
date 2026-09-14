// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen } from '@testing-library/react';
import { useAnimatedNumber, useSequence } from './hooks';

function Sequence() {
  const [on] = useSequence(3, { stepMs: 100, startDelay: 0 });
  return <span data-testid="on">{on}</span>;
}

function Num({ value, from }) {
  return <span data-testid="n">{useAnimatedNumber(value, { from, duration: 300 })}</span>;
}

const allowMotion = (reduce) => vi.stubGlobal('matchMedia', (query) => ({
  matches: reduce, media: query, addEventListener() {}, removeEventListener() {},
}));

afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

it('with reduced motion, sequences and counts show their final real state at once', () => {
  allowMotion(true);
  render(<><Sequence /><Num value={84} from={0} /></>);
  expect(screen.getByTestId('on').textContent).toBe('3');
  expect(screen.getByTestId('n').textContent).toBe('84');
});

it('without matchMedia (tests, old browsers) nothing animates', () => {
  render(<><Sequence /><Num value={42} from={0} /></>);
  expect(screen.getByTestId('on').textContent).toBe('3');
  expect(screen.getByTestId('n').textContent).toBe('42');
});

it('with motion allowed, a sequence reaches every stage and a count ends exactly on the real value', () => {
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'requestAnimationFrame', 'cancelAnimationFrame', 'performance'] });
  allowMotion(false);
  render(<><Sequence /><Num value={42} from={0} /></>);
  expect(screen.getByTestId('on').textContent).toBe('0');
  expect(screen.getByTestId('n').textContent).toBe('0');
  act(() => { vi.advanceTimersByTime(120); });
  expect(Number(screen.getByTestId('on').textContent)).toBeGreaterThan(0);
  act(() => { vi.advanceTimersByTime(600); });
  expect(screen.getByTestId('on').textContent).toBe('3');
  expect(screen.getByTestId('n').textContent).toBe('42');
});
