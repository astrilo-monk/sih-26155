// @vitest-environment jsdom
import { afterEach, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/react';
import Results, { PostureSummary } from './Results';
import { reviewCount } from '../lib/domain';

afterEach(cleanup);

it('a high posture with low coverage is a limited assessment, never Good out of 100', () => {
  const { container } = render(<PostureSummary posture={95} coverage={30} bounds={[0, 100]} criticalUnassessed={['MGMT-005']} />);
  expect(screen.getByText('Limited assessment')).toBeTruthy();
  expect(screen.getByText('Posture 95 · Coverage 30% · Limited assessment')).toBeTruthy();
  expect(container.textContent).not.toContain('/100');
  expect(container.textContent).not.toContain('Good');
});

it('a low posture from one confirmed FAIL at low coverage does not claim the whole device is critical', () => {
  const { container } = render(<PostureSummary posture={0} coverage={11} />);
  expect(screen.getByText('Limited assessment')).toBeTruthy();
  expect(container.textContent).not.toContain('Critical risk');
});

it('unassessed critical controls make the assessment partial; only full coverage is full', () => {
  render(<PostureSummary posture={100} coverage={83} criticalUnassessed={['MGMT-005']} />);
  expect(screen.getByText('Good · partial')).toBeTruthy();
  cleanup();
  const { container } = render(<PostureSummary posture={100} coverage={100} criticalUnassessed={[]} />);
  expect(screen.getByText('Posture 100 · Coverage 100% · Full assessment')).toBeTruthy();
  expect(container.textContent).not.toContain('partial');
});

it('no decided control is not assessed and shows no posture number', () => {
  render(<PostureSummary posture={null} coverage={0} />);
  expect(screen.getAllByText(/Not assessed/).length).toBeGreaterThan(0);
  expect(screen.getByText('—')).toBeTruthy();
});

const SCAN = {
  scan_id: 'scan-1234567', timestamp: '2026-09-14T08:00:00', posture: null, coverage: 0, posture_bounds: [0, 100],
  critical_unassessed: ['MGMT-005'],
  devices: [{ hostname: 'CORE-GATE-07', vendor: 'unknown' }],
  vendor_identification: [{ config_index: 0, detected_vendor: 'unknown', status: 'unknown' }],
  findings: [{ rule_id: 'MGMT-001', severity: 'critical', assurance: 'heuristic', config_index: 0 }],
  results: [
    { config_index: 0, control_id: 'MGMT-001', status: 'fail', assurance: 'heuristic', severity: 'critical' },
    { config_index: 0, control_id: 'MGMT-003', status: 'unknown', assurance: 'ai_verified', proposed_status: 'pass', severity: 'critical' },
    { config_index: 0, control_id: 'MGMT-005', status: 'not_configured', assurance: null, severity: 'critical' },
  ],
  adaptive_configs: [{ config_index: 0, ai_available: true, ai_calls: 1, ai_cache_hits: 0, provisional_reasons: ['Vendor could not be identified'] }],
  frameworks: [],
};

it('review count: provisional readings need human review; decisive failures blocked from automation do not', () => {
  const decisiveFail = (control_id) => ({ config_index: 0, control_id, status: 'fail', assurance: 'parser', severity: 'critical' });
  const scan = {
    results: [decisiveFail('MGMT-005'), decisiveFail('MGMT-008'), decisiveFail('BOUNDARY-001')],
    adaptive_configs: [],
  };
  expect(reviewCount(scan)).toBe(0);

  const withReviewable = {
    ...scan,
    results: [...scan.results, { config_index: 0, control_id: 'MGMT-003', status: 'unknown', assurance: 'ai_verified', proposed_status: 'pass' }],
  };
  expect(reviewCount(withReviewable)).toBe(1);
});

it('keeps provisional material out of decisive counts on an unknown-vendor summary', () => {
  const { container } = render(<Results scan={SCAN} tab="summary" revision={1} />);
  expect(reviewCount(SCAN)).toBe(2);
  expect(screen.getByText(/no confirmed vendor and took the generic analysis path/)).toBeTruthy();
  expect(screen.getByText(/1 listed under Findings/)).toBeTruthy();
  expect(screen.getByRole('img', { name: '0 decisive findings' })).toBeTruthy();
  expect(screen.getByText('Critical control(s) not assessed: MGMT-005')).toBeTruthy();
  expect(screen.getAllByText('Vendor not identified').length).toBe(2);
  expect(container.textContent).toContain('Vendor-specific remediation unavailable');
  expect(screen.getByRole('tab', { name: /Needs your input/ }).textContent).toContain('2');
});
