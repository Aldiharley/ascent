import { writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// Dev-server proxy for the Ascent dashboard backend (src/bin/dashboard.rs).
// The backend deliberately has NO CORS and its request guard requires
// Host in {127.0.0.1:8787, localhost:8787}; POSTs additionally need
// Origin in {http://127.0.0.1:8787, http://localhost:8787} and X-Ascent: 1.
// So the browser talks to Vite (same-origin /api) and Vite forwards to the
// backend: `changeOrigin` rewrites Host, and we pin Origin to the backend's own
// origin so the guard passes without loosening it. Do not add CORS to the backend.
const BACKEND = 'http://127.0.0.1:8787'

// `vite build` empties dist/, which would delete the tracked dist/.gitkeep
// (the Rust backend serves frontend/dist, so the dir must exist in a fresh clone).
// Recreate it after every build so a build never dirties the working tree.
const keepDistGitkeep = {
  name: 'keep-dist-gitkeep',
  closeBundle() {
    writeFileSync(resolve(__dirname, 'dist/.gitkeep'), '')
  },
}

export default defineConfig({
  plugins: [react(), keepDistGitkeep],
  server: {
    proxy: {
      '/api': {
        target: BACKEND,
        changeOrigin: true,
        headers: { Origin: BACKEND },
      },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
  },
})
