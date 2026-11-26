/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Address of the LSADRA API, e.g. http://localhost:8000. Defaults to that when unset. */
  readonly VITE_API_BASE_URL?: string;
  /** `true` serves canned demo data for `testuser` in `npm run dev` only. */
  readonly VITE_DEMO_MOCKS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
