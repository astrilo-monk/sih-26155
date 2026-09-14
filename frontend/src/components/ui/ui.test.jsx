// @vitest-environment jsdom
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import Tabs from './Tabs';
import FileDiff from './FileDiff';
import { Evidence, StatusMark } from './Evidence';

afterEach(cleanup);

const TABS = [{ id: 'a', label: 'Summary' }, { id: 'b', label: 'Findings', count: 3 }, { id: 'c', label: 'Frameworks' }];

it('tabs follow the ARIA tablist keyboard model', () => {
  const onChange = vi.fn();
  render(<Tabs tabs={TABS} active="a" onChange={onChange} idBase="t" />);
  const first = screen.getByRole('tab', { name: 'Summary' });
  expect(first.getAttribute('aria-selected')).toBe('true');
  expect(screen.getByRole('tab', { name: /Findings/ }).tabIndex).toBe(-1);
  fireEvent.keyDown(first, { key: 'ArrowRight' });
  expect(onChange).toHaveBeenLastCalledWith('b');
  fireEvent.keyDown(first, { key: 'ArrowLeft' });
  expect(onChange).toHaveBeenLastCalledWith('c');
  fireEvent.keyDown(first, { key: 'End' });
  expect(onChange).toHaveBeenLastCalledWith('c');
});

it('the diff shows added and removed counts with real line numbers', () => {
  const { container } = render(<FileDiff diff={'@@ -14,1 +14,1 @@\n- transport input telnet ssh\n+ transport input ssh'} file="R1" />);
  expect(screen.getByLabelText('1 added, 1 removed')).toBeTruthy();
  const numbers = [...container.querySelectorAll('.diff-row.del .ln, .diff-row.add .ln')].map((n) => n.textContent);
  expect(numbers).toEqual(['14', '', '', '14']);
});

it('status is never colour-only and evidence keeps its line numbers', () => {
  render(<><StatusMark status="not_configured" /><Evidence lineNumbers={[71]} lines={['  71: remote-console protocol telnet']} /></>);
  expect(screen.getByText('∅')).toBeTruthy();
  expect(screen.getByText('Not configured')).toBeTruthy();
  expect(screen.getByText('71', { selector: '.ln' })).toBeTruthy();
  expect(screen.getByText('remote-console protocol telnet')).toBeTruthy();
});
