# Sewa Setu — Old Age Pension Portal

Department of Social Welfare, Government of Purvanchal. Maintained in-house.

## Running Locally (Docker Compose)

```bash
ADMIN_PASSWORD=pick-a-strong-password SECRET_KEY=pick-a-strong-secret docker compose up --build
```

- Portal: `http://localhost:8000`
- Citizen Status Portal: `http://localhost:8000/status` (OTP-based login for registered mobile numbers)
- Departmental / Officer Login: `http://localhost:8000/admin` (username from `ADMIN_USERNAME` default `admin`, password from `ADMIN_PASSWORD`)
- Evaluation Dashboard: `http://localhost:8000/eval-dashboard`

## Deploying Safely on Render

A Render Blueprint (`render.yaml`) is included at the repository root and provisions:
1. **`sewasetu-db` (Render PostgreSQL)**:
   - Provides `DATABASE_URL` to both the web service and the background scheduler worker.
   - When `DATABASE_URL` is set or `APP_ENV=production` / `RENDER` / `REQUIRE_POSTGRES=1` is active, the portal connects strictly to PostgreSQL ( automatically normalizing `postgres://` URLs to `postgresql://`) and **fails clearly with a `RuntimeError` if PostgreSQL is unavailable**—it never silently falls back to temporary SQLite in production.
   - On first connection to a new PostgreSQL database, `_init_postgres_schema()` safely runs `app/schema.sql` (`CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`) after verifying the file contains no destructive `DROP`, `TRUNCATE`, or `DELETE` statements. Existing tables and records are never deleted or reset.

2. **`sewasetu-web` (Docker Web Service)**:
   - Docker build context: `./app` (`./app/Dockerfile`)
   - Startup command:
     ```bash
     sh -c "exec gunicorn --bind 0.0.0.0:${PORT:-8000} --workers ${WEB_CONCURRENCY:-4} --timeout 30 app:app"
     ```
   - Required environment variables:
     - `DATABASE_URL`: Render PostgreSQL connection string (linked from `sewasetu-db`)
     - `SECRET_KEY`: Strong random Flask session signing key (enforced in production)
     - `ADMIN_USERNAME`: Departmental officer username (default `admin`)
     - `ADMIN_PASSWORD`: Strong non-default officer password (enforced in production)
     - `PUBLIC_BASE_URL`: Canonical HTTPS URL of the Render web service (e.g., `https://sewasetu-web.onrender.com`; also falls back to Render's `RENDER_EXTERNAL_URL`)

3. **`sewasetu-scheduler` (Docker Background Worker — Single Instance)**:
   - Docker build context: `./app` (`./app/Dockerfile`)
   - Startup command:
     ```bash
     python /app/scripts/deemed_approval.py --daemon
     ```
   - Configured with `numInstances: 1` and the same `DATABASE_URL` so the 15-day statutory SLA deemed-approval job runs without duplicate workers.

4. **Public Student Demo SMS/OTP Safety**:
   - Unrestricted SMS gateway console and inbox endpoints (`/__gateway/` and `/__gateway/<path:subpath>`) are **disabled by default (`403 Forbidden`)** and never exposed in production.
   - Neither `/verify` nor `/status/verify` queries or exposes OTPs for arbitrary mobile numbers passed in query parameters (`?mobile=...`).
   - When `DEMO_OTP_DISPLAY=1` (default for the student demo), the generated 6-digit OTP is stored only in the initiating browser's signed Flask session and displayed solely to that session until verified or expired (`DEMO_OTP_DISPLAY=0` disables on-screen OTP hints completely).

5. **File Uploads Note on Render**:
   - Uploaded age-proof documents are stored under `UPLOAD_DIR` (default `/var/sewasetu/uploads`). On Render's free tier, container filesystems are ephemeral across deploys; attach a Render Persistent Disk mounted at `/var/sewasetu/uploads` (single instance) if uploaded PDFs must persist across container rebuilds.

## What the portal does

Citizen flow: mobile + CAPTCHA → OTP verification → personal details → block & dependent village/town address → bank details → age-proof upload → preview and declaration → application number & downloadable PDF acknowledgment. A scheduled background job (`app/scripts/deemed_approval.py`) deems approved any application still `PENDING` after the 15-day statutory SLA.

Rules enforced at submission, in `validate_application()` in `app/app.py`:
applicant is 60 years of age or above; required fields, valid block/village mapping (or explicit manual village entry), and an age-proof document are present; the scheme window is open; and the mobile number holds no other active (`PENDING` / `APPROVED` / `DEEMED_APPROVED`) application. A pending application can be withdrawn from the status portal, after which the same mobile may apply again.

Departmental users see a dashboard, list and filter applications, approve or reject pending ones, and see the audit trail per application.

## Layout

```
app/          Flask application, templates, schema.sql, config, and deemed_approval.py worker
smsgw/        Local-only simulated SMS gateway (disabled in production)
tests/        End-to-end regression, security, OAuth 2.1 PKCE, MCP, and deployment readiness tests
render.yaml   Render Blueprint for web service, single-instance scheduler worker, and PostgreSQL
```

## Letting other applications act for a citizen or an officer

Sewa Setu is also an **OAuth 2.1 authorization server**. A third-party application can act
for a citizen (scope `citizen`) or for a block officer (scope `officer`) once that person
signs in on the portal and approves it. Citizens sign in by mobile and OTP, officers with the
departmental login. The application never handles the OTP or the password.

- Discovery: `/.well-known/oauth-authorization-server` (RFC 8414)
- Registration: `/oauth/register` (RFC 7591), or a client ID metadata document URL as `client_id`
- Authorization: `/oauth/authorize` (authorization code with PKCE S256; the `resource` the
  application asks for becomes the token's audience, RFC 8707)
- Tokens: `/oauth/token`. Access tokens are RS256 JWTs. A sign-in is a **session with an
  absolute end**: 2 hours for a citizen, 8 hours for an officer, counted from the consent.
  Access tokens are short (20 / 30 minutes) and refresh tokens rotate within the session but
  never extend it; after it ends the person signs in again. Portals are used on shared phones
  and kiosks.
- Sign-out: `/oauth/revoke` (RFC 7009). People can also end any sign-in from the status
  portal (**Connected applications**) or, for officers, the admin dashboard.
- Keys: `/.well-known/jwks.json`

A service that receives one of these tokens verifies it with the JWKS, checks `iss` is this
portal, checks `aud` is its own canonical URL, and reads `scope`, `role` and `sub`
(`citizen:<mobile>` or `officer:<username>`).

Long-lived **program tokens** for unattended use (role officer) are issued by an
administrator at `/admin/tokens`.
