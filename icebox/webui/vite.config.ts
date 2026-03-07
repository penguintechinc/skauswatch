import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
  define: {
    'import.meta.env.VITE_BUILD_TIME': JSON.stringify(
      Math.floor(Date.now() / 1000)
    ),
    'import.meta.env.VITE_VERSION': JSON.stringify(
      process.env.npm_package_version || '0.0.0'
    ),
  },
});
