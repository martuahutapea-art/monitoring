# SIMON PRAKERIN — PostgreSQL edition

## Environment variables
Set `DATABASE_URL` to the Neon pooled connection string and `SESSION_SECRET` to a random secret of at least 32 characters. Set `NODE_ENV=production` on the hosting provider. Never commit `.env` or credentials to GitHub.

## Database
The application creates the required PostgreSQL tables on startup: `users`, `attendance`, `journals`, `audit_logs`, and `user_sessions` (session table managed by connect-pg-simple).

## Demo users
No demo accounts are created by default. For local testing only, set `SEED_DEMO=true` and set strong `DEMO_*_PASSWORD` values. Do not enable demo seeding in production.

## Geofence
`COMPANY_LAT`, `COMPANY_LON`, and `GEOFENCE_RADIUS_METERS` are example values and must be replaced with the approved workplace coordinates and radius before real use. Browser GPS is not proof against spoofing; do not rely on GPS alone for disciplinary or payroll decisions.
