import { defineConfig } from 'vite'
import { configDefaults } from 'vitest/config'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  // e2e/ is Playwright's (npx playwright test), not vitest's
  test: { exclude: [...configDefaults.exclude, 'e2e/**'] },
})
