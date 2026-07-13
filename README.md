# Coast Medical Service — TOA Escalations Portal

Flask app matching the stack/pattern used by the Feature Request portal
(GitHub + Render + Microsoft 365/Graph email).

## Local run
```
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app.py
flask seed-admin      # creates an initial Admin user
python app.py         # http://localhost:5000
```
Default seeded admin: eitan.margolis1@gmail.com / ChangeMe123! (override via
SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD env vars) — change the password after
first login via Manage Users.

## Deploy to Render (same pattern as the Feature Request portal)
1. Push this folder to a new GitHub repo, e.g. `toa-escalations-portal`.
2. In Render: New → Web Service → connect the repo.
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn app:app`
3. Add a Postgres database (Render → New → PostgreSQL) and set `DATABASE_URL`
   on the web service to its connection string (falls back to SQLite if unset —
   fine for testing, but SQLite resets on every deploy on Render).
4. Environment variables to set on the web service:
   - `SECRET_KEY` — any random string
   - `APP_BASE_URL` — e.g. `https://toa-escalations.onrender.com`
   - `MS_TENANT_ID`, `MS_CLIENT_ID`, `MS_CLIENT_SECRET`, `MS_SENDER_UPN` —
     same Azure app registration/values used for the Feature Request portal
     (or a new app registration with Mail.Send permission)
   - `SEED_ADMIN_EMAIL`, `SEED_ADMIN_PASSWORD` — optional, for the first admin
5. After first deploy, run `flask seed-admin` from the Render shell (or add it
   as a one-off job) to create your first Admin login, then use Manage Users
   to add everyone else.

## Branding
Colors/logo are placeholders in `static/style.css` (`--brand-primary`,
`--brand-accent`) and the topbar logo mark in `templates/base.html`. Swap in
the real Coast Medical Service logo file and hex colors once provided and
these will match the Feature Request portal.

## Roles
- **Admin** — all tabs, all fields, only role that can access Manage Users.
- **Manager** — all tabs except Manage Users; can set Status to a closed value
  (Denied / Closed - Resolved / Closed - Canceled).
- **User** — all tabs except Manage Users; cannot set Status to a closed value.

## Business logic implemented
- My Open Escalations shows records where the current user is Recruiter,
  Sales Rep, Compliance Specialist, Recruiter Manager, or Action To, and
  Status is Open / Pending Approval / Clinical Acknowledged.
- Recruiter Manager is auto-set from the selected Recruiter's Manager field
  at creation time.
- Validation rules: Action To change requires an Action Item change; Best Day
  to Call Traveler requires Best Time + Time Zone; only Manager/Admin can set
  a closed Status.
- Email automations: new Escalation notifies Recruiter/Sales Rep/Compliance
  Specialist/Recruiter Manager; Action To change notifies the new Action To
  user; chatter comments notify @mentioned users and prior participants.
- Reporting tab: pick columns from the page layout, Type/Status quick
  filters, dynamic AND/OR filter builder, and saved report views.
