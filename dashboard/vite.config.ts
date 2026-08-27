import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/control-api": {
        target: process.env.VITE_CONTROL_SERVICE_URL ?? "http://127.0.0.1:8082",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/control-api/, "")
      },
      "/gateway-api": {
        target: process.env.VITE_GATEWAY_URL ?? "http://127.0.0.1:8080",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/gateway-api/, "")
      },
      "/sensor-api": {
        target: process.env.VITE_NETWORK_SENSOR_URL ?? "http://127.0.0.1:8083",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/sensor-api/, "")
      }
    }
  }
});
