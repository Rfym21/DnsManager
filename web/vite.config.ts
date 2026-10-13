import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { fileURLToPath, URL } from 'node:url'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: { proxy: { '/api': process.env.DNSMGR_API_TARGET ?? 'http://127.0.0.1:18081', '/health': process.env.DNSMGR_API_TARGET ?? 'http://127.0.0.1:18081' } },
  build: {
    outDir: fileURLToPath(new URL('../server/internal/webui/dist', import.meta.url)),
    emptyOutDir: true,
    chunkSizeWarningLimit: 600,
  },
  test: { include: ['src/**/*.test.{ts,tsx}'], environment: 'jsdom', setupFiles: ['./src/test/setup.ts'], restoreMocks: true },
})
