import { defineConfig } from "vite";

export default defineConfig({
  build: { target: "es2022", sourcemap: false },
  worker: { format: "es" },
  server: {
    host: "127.0.0.1",
    fs: { strict: true, deny: [".env", ".env.*", "*.{crt,pem}", "**/.git/**", "**/.local/**", "**/.cache/{npm,pip,pycache,xdg}/**"] },
  },
});
