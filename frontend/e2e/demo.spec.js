// The 2-minute judge path (docs/demo.md), in a real browser against the real backend.
import { expect, test } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const demo = (name) => fileURLToPath(new URL(`../../demo-sih/${name}`, import.meta.url));

test('scan two vendors, follow an attack path, verify a report against the ledger', async ({ page }, info) => {
  // 1. New scan: Cisco + PAN-OS, high criticality, internet-facing
  await page.goto('/#/app');
  await page.locator('#config-files').setInputFiles([demo('cisco_edge_vulnerable.cfg'), demo('paloalto_fw_vulnerable.cfg')]);
  await page.getByRole('combobox', { name: 'How important is this device?' }).selectOption('high');
  await page.getByLabel('This device faces the internet').check();
  await page.getByRole('button', { name: 'Start scan' }).click();

  // 2. Overview: critical risk, both devices, problems visible only across devices
  await expect(page.getByText(/critical/i).first()).toBeVisible({ timeout: 60_000 });
  await expect(page.getByRole('heading', { name: 'Across 2 devices' })).toBeVisible();
  await expect(page.getByText('The same SNMP community string is used on 2 devices')).toBeVisible();
  await expect(page.getByRole('button', { name: 'See attack paths' })).toBeVisible();

  // 3. Same vendor-neutral fields from two different syntaxes
  await page.getByRole('button', { name: 'Compare the devices field by field' }).click();
  await expect(page.getByText('mgmt.ssh.version').first()).toBeVisible({ timeout: 30_000 });

  // 4. Executive summary PDF, then the ledger recognises exactly that file
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: 'Executive summary (PDF)' }).click();
  const pdf = info.outputPath('executive.zip'); // two devices: one PDF each, in a .zip
  await (await download).saveAs(pdf);

  // 6. Attack paths, on their own page, each breakable by one fix
  await page.getByRole('link', { name: /^Attack paths/ }).click();
  await expect(page.getByRole('heading', { name: 'Potential attack paths' })).toBeVisible();
  await expect(page.getByText('Remote takeover through the management plane').first()).toBeVisible();

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

  // 7. Rules catalog: every check and the requirements it answers
  await page.getByRole('link', { name: 'Rules catalog' }).click();
  await expect(page.getByText(/78/).first()).toBeVisible();
});
