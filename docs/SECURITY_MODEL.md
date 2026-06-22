# LuminaFPM — Security Model

> Authoritative source: **Volume 12** (Security Architecture) + V1 §16, V3 §14, V13 §5.
> LuminaFPM stores firewall inventory, policies, credentials, anomalies, and reports — it is a
> **sensitive security management system** and must be treated as one.

> ⚠️ Current state (prior review): **zero backend auth**, **fake client-side login** (hardcoded
> `demo`/`123456`), **CORS `*` + credentials**, firewall secrets not encrypted, Postgres/Redis
> exposed. Every item below is required to close those gaps.

---

## 1. Read-only enforcement (V12 §3) — the cardinal rule
- Connectors call **read-only** endpoints only (GET / show / monitor / keygen / op-show).
- **Forbidden in code (v1):** FortiGate config `set/edit/delete`; PAN `set/edit/delete/move`; PAN
  `commit`; rule enable/disable; object/service modification; policy push (V3 Table 24).
- Firewall API accounts use **least-privilege read** permissions.
- **Code review must reject** any write-capable firewall operation.
- UI must contain **no remediation buttons** that push changes. The platform recommends; authorized
  humans apply changes outside LuminaFPM.

## 2. Trust boundaries (V12 Table 2)
| Boundary | Risk | Control |
|---|---|---|
| Browser ↔ backend | Unauthorized access / data exposure | TLS, auth, RBAC |
| Backend ↔ DB | Leakage / injection | ORM parameterized queries, least privilege |
| Backend/workers ↔ firewalls | Credential misuse | read-only accounts, encrypted secrets |
| Backend ↔ CTI/LLM | Sensitive data leakage | data minimization, provider controls, local Ollama option |
| Docker network | Service exposure | private networks, restricted ports |

## 3. Authentication (V12 Table 3)
- Secure **session or JWT** with expiration + inactivity timeout.
- Local-auth passwords hashed with a modern algorithm (argon2/bcrypt).
- Separate service accounts from human users. MFA recommended for production.
- Replace the cosmetic frontend login with a **real backend auth flow**; the API enforces auth on
  every route via a FastAPI dependency/middleware (not the client).

## 4. Authorization / RBAC (V12 Table 4, V1 Table 16)
| Role | Allowed |
|---|---|
| Platform Admin | users, settings, credentials, providers, polling schedules |
| Firewall Engineer | view devices/policies/anomalies/risks/reports; trigger read-only polls |
| SOC Analyst | view risk/CTI/reports/anomaly evidence |
| Auditor | read-only reports/evidence/benchmark outputs |
| Viewer | dashboard-only |
RBAC enforced server-side (middleware/dependency). Frontend hides controls not permitted by role,
but the **server is authoritative**.

## 5. Credentials & secrets (V12 §6, V3 §6.2)
- Never in source code, env examples, frontend state, browser storage, or logs.
- Firewall tokens / PAN API keys / LLM+CTI provider keys **encrypted at rest** (`ENCRYPTION_KEY`),
  decrypted only in backend/worker memory.
- Frontend never receives plaintext secrets; credential-test endpoints return **status only**.
- Support **rotation** without recreating the device record. Different creds per lab/staging/prod.
- Log credential **usage events** (secret id, target, timestamp) — never the value.
- Implemented by the `device_credential` table (encrypted) — see DATABASE_SCHEMA_V4 §10.

## 6. API security (V12 Table 5)
Pydantic request validation · SQLAlchemy parameterized queries · **restricted CORS allowlist**
(`CORS_ALLOWED_ORIGINS`; never `*` with credentials) · rate-limit login + expensive job-creation ·
authorize every export · no secrets/stack traces in error responses.

## 7. Data protection (V12 §8)
Treat rules, object names, management IPs, reports as sensitive. Encrypt DB backups. Redact secrets
from logs. Config flag to suppress sending internal indicators to external CTI/LLM. Define retention
for raw snapshots, CTI observations, AI reports.

## 8. Audit logging (V12 Table 6) — `audit_log`
Must log: user login/logout (user, ts, IP, result) · device poll triggered · credential used (id,
target, ts; never value) · anomaly run (scope, run id, count, status) · risk recalculation · report
generated (user, report id, evidence ids) · suppression/accepted-risk (user, reason, expiry, finding).
Audit tables protected against casual deletion.

## 9. CTI & LLM security (V12 §10, V9 §11)
Send minimum required data to providers; support **local Ollama** for privacy. Treat CTI/scraped text
as **untrusted** — prevent prompt injection. Store LLM output with evidence refs + provider metadata,
labeling generated analysis vs source evidence. **Never** send private RFC1918/internal hostnames to
external providers unless explicitly configured. No uncontrolled dark-web scraping in v1.

## 10. Database security (V12 Table 7)
Least-privilege DB user for the API; only the migration runner alters schema (Alembic); encrypted
access-controlled backups; PII minimization.

## 11. Deployment hardening (V12 §12, V13 §5)
- **Do not expose Postgres/Redis publicly** (internal Docker network only).
- Env vars / secret manager for config; least-privilege containers; dependency scanning in CI;
  HTTPS in production; centralized access-controlled logs.

## 12. Incident & failure handling (V12 Table 8)
Firewall auth fail → mark `authentication_failed`, no endless retry. CTI provider down → CTI job
partial/failed, **anomaly dashboard unaffected**. LLM down → deterministic report without AI summary.
DB unavailable → fail safe, preserve queue state. Suspicious activity → log + admin review.

## 13. Developer checklist (V12 §14)
RBAC middleware · encrypted secret storage · connector read-only audit · API authN/Z on all routes ·
audit logs for critical actions · Postgres/Redis not externally exposed · LLM/CTI data-minimization
controls.
