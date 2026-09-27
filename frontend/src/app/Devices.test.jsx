// @vitest-environment jsdom
import { expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import Devices from './Devices';

const SCAN = {
  scan_id: 's1', results: [], findings: [], adaptive_configs: [], vendor_identification: [],
  devices: [{
    hostname: 'edge1', vendor: 'cisco_ios', os_version: '15.2(4)M11',
    known_cves: {
      platform: 'cisco_ios', train: '15.2', critical: 3, high: 71, cache_date: '2026-09-28',
      caveat: 'Matched on the stated software version: a specific build may already carry the fix. This is context, not an assessment.',
      top: [{ id: 'CVE-2017-12240', score: 9.8, url: 'https://nvd.nist.gov/vuln/detail/CVE-2017-12240' }],
    },
  }],
};

it('shows the known CVEs of the stated version as context, with the caveat and a link to NVD', () => {
  render(<Devices scan={SCAN} audit={{ plan: null }} />);
  screen.getByText('Known CVEs for 15.2');
  expect(screen.getByRole('link', { name: 'CVE-2017-12240' }).getAttribute('href')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2017-12240');
  screen.getByText(/context, not an assessment/);
});
