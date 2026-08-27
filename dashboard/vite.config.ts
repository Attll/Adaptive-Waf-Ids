import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const control = process.env.VITE_CONTROL_SERVICE_URL ?? "http://127.0.0.1:8082";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/control-api": {
        target: control,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/control-api/, "")
      },
      "/control-ws": {
        target: control.replace(/^http/, "ws"),
        ws: true,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/control-ws/, "")
      },
      "/gateway-api": {
        target: process.env.VITE_GATEWAY_URL ?? "http://127.0.0.1:8080",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/gateway-api/, "")
      },
      "/detection-api": {
        target: process.env.VITE_DETECTION_SERVICE_URL ?? "http://127.0.0.1:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/detection-api/, "")
      },
      "/sensor-api": {
        target: process.env.VITE_NETWORK_SENSOR_URL ?? "http://127.0.0.1:8083",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/sensor-api/, "")
      },
      "/adaptation-api": {
        target: process.env.VITE_ADAPTATION_SERVICE_URL ?? "http://127.0.0.1:8084",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/adaptation-api/, "")
      }
    }
  }
});
