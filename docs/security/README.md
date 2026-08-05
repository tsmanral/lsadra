# Security

- **Reporting a vulnerability:** see the repository
  [SECURITY.md](../../SECURITY.md) — private reporting via GitHub advisory or
  email; 72-hour acknowledgement, 7-day triage target.
- **Do not** open public issues for vulnerabilities.

## Posture (defensive)

- Configuration **fails closed** by default outside development mode (a stable
  JWT secret is mandatory; TLS enforcement is on).
- Logs are treated as **attacker-controlled input** to parsers, the LLM, and the
  RAG index.
- Full-history secret scanning runs weekly in CI (gitleaks on PRs + a scheduled
  verified TruffleHog sweep).
