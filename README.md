
# CAD/MDT Starter (Express + SQLite)

A minimal, self-hostable CAD/MDT for roleplay servers.

## Features
- Roles: `DISPATCH`, `OFFICER`, `FIREEMS`, `CIVILIAN`, `ADMIN`
- Login/register, session-based auth
- Dashboard with calls, units, BOLOs
- Dispatch console to assign units and update call status
- Civilian characters
- Simple officer/fire/EMS reports (citation, arrest, incident)
- Lookups: plate and person (local DB)
- SQLite file persistence

## Quick Start
1. Install Node 18+
2. In the project folder, run:
   ```bash
   npm install
   npm run dev
   ```
3. Open http://localhost:3000

**Demo logins**
- admin / admin123
- dispatch / dispatch123
- officer1 / officer123
- fire1 / fire123
- civ1 / civ123

## Deploy
- **Render**: create a Web Service, build command `npm install`, start command `npm start`
- **Railway/Dokku/Docker**: add a Dockerfile or run `node server.js`
- **Reverse Proxy**: serve behind Nginx/Caddy with HTTPS

## Notes
- Default session storage is memory; for production use Redis or a DB store.
- Set `SESSION_SECRET` env var in production.
- DB file: `cadmdt.sqlite` (back it up).

## Extend Ideas
- Permissions per department
- Unit creation UI and multi-user linking
- NCIC-style records, warrants, citations library
- Call timeline & comments
- WebSocket live updates
- Audit logs
