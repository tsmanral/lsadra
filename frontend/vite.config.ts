import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// G-11: production builds carry a Content-Security-Policy. Scripts and styles
// load only from the dashboard's own origin, so injected markup cannot run
// script or exfiltrate the session token through <script>, <object> or <base>.
// API calls (connect-src) may go to the API on another origin or port. Not
// applied to `npm run dev`, whose React refresh preamble is an inline script.
// frame-ancestors cannot be set from a <meta> tag; serve it as a header (the
// API already sends frame-ancestors 'none').
export const DASHBOARD_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "connect-src 'self' http: https: ws: wss:",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
].join('; ')

const cspMeta = (): Plugin => ({
  name: 'lsadra-csp-meta',
  apply: 'build',
  transformIndexHtml: () => [
    { tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: DASHBOARD_CSP }, injectTo: 'head-prepend' },
    { tag: 'meta', attrs: { name: 'referrer', content: 'no-referrer' }, injectTo: 'head-prepend' },
  ],
})

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss(), cspMeta()],
})
