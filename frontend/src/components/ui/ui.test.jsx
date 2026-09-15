// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import FileDiff from './FileDiff';
import { Evidence, StatusMark } from './Evidence';

afterEach(cleanup);

it('the diff shows added and removed counts with real line numbers', () => {
  const { container } = render(<FileDiff diff={'@@ -14,1 +14,1 @@\n- transport input telnet ssh\n+ transport input ssh'} file="R1" />);
  expect(screen.getByLabelText('1 added, 1 removed')).toBeTruthy();
  const numbers = [...container.querySelectorAll('.diff-row.del .ln, .diff-row.add .ln')].map((n) => n.textContent);
  expect(numbers).toEqual(['14', '', '', '14']);
});

it('status is never colour-only and evidence keeps its line numbers', () => {
  render(<><StatusMark state="not_configured" /><Evidence lineNumbers={[71]} lines={['  71: remote-console protocol telnet']} /></>);
  expect(screen.getByText('∅')).toBeTruthy();
  expect(screen.getByText('Not configured')).toBeTruthy();
  expect(screen.getByText('71', { selector: '.ln' })).toBeTruthy();
  expect(screen.getByText('remote-console protocol telnet')).toBeTruthy();
});
