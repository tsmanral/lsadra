# LSADRA dashboard (frontend)

The React SOC dashboard for LSADRA: Command Center, Live Stream, Investigate, Response, Analytics,
Threat Intel, Sources, Device Behavior, Feedback and Admin pages. Built with React 19, TypeScript,
Vite, Tailwind CSS, TanStack Query, Zustand and Recharts.

## Run it locally

You need Node.js 22 or newer (CI uses Node 24) and the LSADRA API running on port 8000 in dev mode
with CORS allowing this origin. The [contributing guide](../CONTRIBUTING.md#development-setup)
has the exact commands, including how to load synthetic demo data.

```bash
npm ci          # install the exact versions in package-lock.json
npm run dev     # http://localhost:5173
```

Log in with an account you registered, or with the `demo.admin` user that
`scripts/seed_demo.py` creates.

## Where things are

| Path | What it holds |
|---|---|
| `src/pages/` | One file per dashboard page |
| `src/layouts/DashboardLayout.tsx` | Sidebar, header and the page frame |
| `src/components/` | Shared components |
| `src/services/api.ts` | Every REST call, and `API_BASE_URL` (the API address) |
| `src/services/alertStream.ts` | The authenticated `/ws/alerts` stream with REST backfill |

Keep API calls in `src/services/`, not inside components. Authorization is enforced by the API;
the dashboard only hides what a role can't use.

## Checks

CI runs all of these on every pull request:

```bash
npx tsc -b --noEmit   # type check
npm run build         # production build into dist/
npx eslint .          # lint
```

ESLint still reports existing errors, mostly `no-explicit-any`. CI fails only if a PR raises the
error count above the baseline recorded in `.github/workflows/ci.yml`. Cleaning up one page at a
time is a good first contribution: fix the errors in that file and lower the baseline in the same PR.
