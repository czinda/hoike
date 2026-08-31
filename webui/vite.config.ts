import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/ui/',
  server: {
    port: 9000,
    proxy: {
      '/api/admin': {
        target: 'http://localhost:2560',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
  },
});
