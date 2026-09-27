// The 2-minute judge path (docs/demo.md), in a real browser against the real backend. Each step is timed and the
// timings are written next to the test output (demo-timings.json), so docs/demo.md quotes measured seconds.
import { expect, test } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const demo = (name) => fileURLToPath(new URL(`../../demo-sih/${name}`, import.meta.url));
const FILES = ['cisco_edge_vulnerable.cfg', 'paloalto_fw_vulnerable.cfg', 'juniper_edge_braces.conf', 'aws_edge.tf'];

test('scan four dialects, follow a proved attack path, see CVE context, verify a report', async ({ page }, info) => {
  const timings = [];
  let last = Date.now();
  const mark = (step) => { const now = Date.now(); timings.push({ step, seconds: (now - last) / 1000 }); last = now; };

  // 1. One scan: Cisco IOS (parser), PAN-OS, brace-style Junos and Terraform (generic engine + seeds)
  await page.goto('/#/app');
  await page.locator('#config-files').setInputFiles(FILES.map(demo));
  await page.getByRole('combobox', { name: 'How important is this device?' }).selectOption('high');
  await page.getByLabel('This device faces the internet').check();
  await page.getByRole('button', { name: 'Start scan' }).click();

  // 2. Overview: critical risk, four devices, problems visible only across devices
  await expect(page.getByText(/critical/i).first()).toBeVisible({ timeout: 90_000 });
  await expect(page.getByRole('heading', { name: 'Across 4 devices' })).toBeVisible();
  await expect(page.getByText('The same SNMP community string is used on 2 devices')).toBeVisible();
  mark('upload 4 files and scan');

  // 3. Same vendor-neutral fields from different syntaxes
  await page.getByRole('button', { name: 'Compare the devices field by field' }).click();
  await expect(page.getByText('mgmt.ssh.version').first()).toBeVisible({ timeout: 30_000 });
  mark('compare the devices field by field');

  // 4. Devices: each platform as read, and the CVE context of the stated Cisco release
  await page.getByRole('link', { name: 'Devices', exact: true }).click();
  await expect(page.getByText(/Known CVEs for 16\.9/)).toBeVisible();
  await expect(page.getByText(/context, not an assessment/).first()).toBeVisible();
  mark('devices and CVE context');

  // 5. Attack paths, each breakable by one fix, and the proof of every chain
  await page.getByRole('link', { name: /^Attack paths/ }).click();
  await expect(page.getByRole('heading', { name: 'Potential attack paths' })).toBeVisible();
  await expect(page.getByText('Remote takeover through the management plane').first()).toBeVisible();
  await expect(page.getByText(/checked against a positive and a negative configuration/)).toBeVisible();
  mark('attack paths and their proof');

  // 6. Executive summary PDF, then the ledger recognises exactly that file
  await page.getByRole('link', { name: 'Overview' }).click();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Executive summary (PDF)' }).click();
  const pdf = info.outputPath('executive.zip'); // several devices: one PDF each, in a .zip
  await (await download).saveAs(pdf);
  mark('download the executive PDFs');

  await page.getByRole('link', { name: 'Audit ledger' }).click();
  await page.getByRole('button', { name: 'Verify the ledger' }).click();
  await expect(page.getByText(/^Intact:/)).toBeVisible();
  const upload = page.locator('input[type=file][accept*="zip"]');
  await upload.setInputFiles(pdf);
  await expect(page.getByText(/^Genuine:/)).toBeVisible();
  const forged = readFileSync(pdf);
  forged[Math.floor(forged.length / 2)] ^= 1;
  writeFileSync(info.outputPath('forged.zip'), forged);
  await upload.setInputFiles(info.outputPath('forged.zip'));
  await expect(page.getByText(/^Not found:/)).toBeVisible();
  mark('verify the ledger and the report');

  // 7. Rules catalog: every check and the requirements it answers
  await page.getByRole('link', { name: 'Rules catalog' }).click();
  await expect(page.getByText(/78/).first()).toBeVisible();
  mark('rules catalog');

  writeFileSync(info.outputPath('demo-timings.json'), JSON.stringify(timings, null, 2));
  console.log(JSON.stringify(timings));
});
