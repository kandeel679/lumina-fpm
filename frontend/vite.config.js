import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Proxy target. In Docker Compose the frontend service sets VITE_API_PROXY to
// `http://api:8000` (reach the backend by service name). On the host the var is
// unset, so we default to the published backend port for `npm run dev`.
const apiTarget = process.env.VITE_API_PROXY || 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api/v1': {
        target: apiTarget,
        changeOrigin: true,
      },
    },
  },
})
