// End-to-end: the real backend and frontend on their own ports, a throwaway database, AI off, nothing from .env.
//   npx playwright test            (Windows: installed Chrome, or PW_CHANNEL=msedge; elsewhere: npx playwright install chromium)
import { defineConfig } from '@playwright/test';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const python = process.platform === 'win32' ? '"venv/Scripts/python.exe"' : 'venv/bin/python';
const db = join(mkdtempSync(join(tmpdir(), 'netaudit-e2e-')), 'e2e.db');

export default defineConfig({
  testDir: 'e2e',
  timeout: 120_000,
  use: {
    baseURL: 'http://localhost:5183',
    channel: process.env.PW_CHANNEL || (process.platform === 'win32' ? 'chrome' : undefined),
    acceptDownloads: true,
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      command: `${python} -m uvicorn app.main:app --port 8011`,
      cwd: '../backend',
      url: 'http://localhost:8011/health',
      timeout: 120_000,
      env: { ADAPTIVE_DB_PATH: db, DATABASE_URL: '', API_KEY: '', LOCAL_AI_URL: '', GROQ_API_KEY: '', GROQ_API_KEY_1: '',
        GROQ_API_KEY_2: '', GROQ_API_KEY_3: '', GROQ_API_KEY_4: '' },
    },
    {
      command: 'npx vite --port 5183 --strictPort',
      url: 'http://localhost:5183',
      env: { VITE_API_BASE_URL: 'http://localhost:8011/api' },
    },
  ],
});
