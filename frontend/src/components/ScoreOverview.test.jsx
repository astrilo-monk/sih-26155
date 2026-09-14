// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import ScoreOverview from './ScoreOverview';

afterEach(cleanup);

const renderPosture = (props) =>
  render(<ScoreOverview critical={0} high={0} medium={0} low={0} bounds={[0, 100]} {...props} />);

it('a high posture with low coverage is a limited assessment, never GOOD out of 100', () => {
  const { container } = renderPosture({ score: 95, coverage: 30, criticalUnassessed: ['MGMT-005'] });
  expect(screen.getByText('LIMITED ASSESSMENT')).toBeTruthy();
  expect(screen.getByText('Posture 95 · Coverage 30% · Limited assessment')).toBeTruthy();
  expect(container.textContent).not.toContain('/100');
  expect(container.textContent).not.toContain('GOOD');
});

it('a low posture from one confirmed FAIL at low coverage does not claim the whole device is critical', () => {
  const { container } = renderPosture({ score: 0, coverage: 11, critical: 1 });
  expect(screen.getByText('LIMITED ASSESSMENT')).toBeTruthy();
  expect(container.textContent).not.toContain('CRITICAL RISK');
  expect(container.textContent).not.toContain('Immediate remediation required');
});

it('unassessed critical controls make the assessment partial', () => {
  renderPosture({ score: 100, coverage: 83, criticalUnassessed: ['MGMT-005'] });
  expect(screen.getByText('GOOD · PARTIAL')).toBeTruthy();
  expect(screen.getByText('Posture 100 · Coverage 83% · Partial assessment')).toBeTruthy();
  expect(screen.getByText(/Critical control\(s\) not assessed: MGMT-005/)).toBeTruthy();
});

it('only full coverage with every critical control decided is a full assessment', () => {
  const { container } = renderPosture({ score: 100, coverage: 100, criticalUnassessed: [] });
  expect(screen.getByText('GOOD')).toBeTruthy();
  expect(screen.getByText('Posture 100 · Coverage 100% · Full assessment')).toBeTruthy();
  expect(container.textContent).not.toContain('PARTIAL');
});

it('no decided control is not assessed', () => {
  renderPosture({ score: null, coverage: 0 });
  expect(screen.getByText('NOT ASSESSED')).toBeTruthy();
});
