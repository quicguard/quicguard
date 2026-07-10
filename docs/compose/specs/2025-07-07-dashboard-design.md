# QuicGuard Management Dashboard

> [!NOTE]
> This document may not reflect the current implementation.
> See the final report for up-to-date state:
> [Final Report](../reports/dashboard.md)

## [S1] Problem

QuicGuard stores per-organization configs (TLS certs, auth, upstream, policies) in Redis, currently seeded via scripts. There is no web interface for managing these configs. Customers need a dashboard to manage their own organization configs, and admins need a way to create/approve customers.

## [S2] Solution Overview

Build a management dashboard as a new `dashboard` crate in the workspace:
- **Backend**: Axum server with JWT auth, RBAC, Postgres for user/org persistence, real-time Redis sync
- **Frontend**: Svelte SPA served as static files by Axum
- **Roles**: Admin (manage users, all orgs) and Customer (manage own orgs, pending approval)
- **Infrastructure**: Postgres added to Docker Compose with host-mounted volume, setup script

## [S3] Architecture

```
Svelte SPA ──▶ Axum Backend ──▶ Postgres (users, orgs)
                    │
                    └──────────▶ Redis (pubsub + org configs)
```

New workspace crate: `dashboard/` with its own Cargo.toml.
The existing QUIC server picks up config changes via Redis pubsub (no changes needed).

## [S4] Data Model

### users table
| Column | Type | Notes |
|--------|------|-------|
| id | UUID PK | gen_random_uuid() |
| email | VARCHAR(255) UNIQUE | login identifier |
| password_hash | VARCHAR(255) | bcrypt hashed |
| role | VARCHAR(20) | 'admin' or 'customer' |
| approved | BOOLEAN | false until admin approves |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

### organizations table
| Column | Type | Notes |
|--------|------|-------|
| id | VARCHAR(64) PK | matches Redis key |
| owner_id | UUID FK→users | owner user id |
| name | VARCHAR(255) | display name |
| config | JSONB | full org config matching konfig::Organization schema |
| created_at | TIMESTAMPTZ | |
| updated_at | TIMESTAMPTZ | |

## [S5] API Endpoints

### Auth
- `POST /api/auth/signup` — register (creates unapproved user)
- `POST /api/auth/login` — returns JWT if approved
- `GET /api/auth/me` — current user info

### Admin
- `GET /api/admin/users` — list all users
- `PUT /api/admin/users/:id/approve` — approve a user
- `DELETE /api/admin/users/:id` — delete a user
- `GET /api/admin/organizations` — list all organizations

### Customer
- `GET /api/organizations` — list own organizations
- `POST /api/organizations` — create org (syncs to Redis)
- `PUT /api/organizations/:id` — update org config (syncs to Redis)
- `DELETE /api/organizations/:id` — delete org (syncs to Redis)

## [S6] Auth & RBAC

- JWT: HS256, 24h expiry, payload `{ sub, email, role, exp }`
- Password: bcrypt with cost 12
- Middleware extracts JWT from `Authorization: Bearer` header
- Unapproved users get 403 on login
- Admin routes reject non-admin users
- Customer org routes reject users accessing other users' orgs

## [S7] Redis Sync

On every org create/update/delete:
1. Write to Postgres (transactional)
2. `HSET quicguard:organizations <org_id> <json>` — update Redis hash
3. `PUBLISH quicguard:updates <OrgUpdate JSON>` — notify QUIC server

Reuses the existing `OrgUpdate` format from `konfig/src/lib.rs`.

## [S8] Frontend

Svelte SPA with pages:
- `/login` — email/password login
- `/signup` — registration form
- `/dashboard` — role-based dashboard
  - Admin: user list with approve buttons, all orgs overview
  - Customer: own orgs list, create/edit/delete with JSON config editor
- Built with Vite, output to `dashboard/static/`
- Axum serves static files with SPA fallback

## [S9] Infrastructure

### Docker Compose changes (services/services.yaml)
- Add `postgres` service with host-mounted volume for data persistence
- Port 5432 exposed
- Config via env vars (POSTGRES_DB, POSTGRES_USER, POSTGRES_PASSWORD)

### Config file
- `dashboard/.env` with: DATABASE_URL, REDIS_URL, JWT_SECRET, SERVER_PORT
- Loaded via `dotenvy` crate

### Setup script
- `dashboard/scripts/setup.sh` — runs SQL migrations, creates initial admin, builds frontend

## [S10] Migration from existing Redis-seeded configs

Existing Redis org configs remain intact. The dashboard reads org config structure from Postgres JSONB and syncs to Redis. No data migration needed — both sources coexist.

## [S11] File Structure

```
dashboard/
├── Cargo.toml
├── .env.example
├── migrations/
│   └── 001_initial.sql
├── scripts/
│   └── setup.sh
├── src/
│   ├── main.rs           # entry point, server startup
│   ├── config.rs         # env config loading
│   ├── db.rs             # Postgres connection pool
│   ├── auth.rs           # JWT creation/validation, password hashing
│   ├── middleware.rs     # auth extraction, RBAC guards
│   ├── routes/
│   │   ├── mod.rs
│   │   ├── auth.rs       # signup, login, me
│   │   ├── admin.rs      # user management, org listing
│   │   └── organizations.rs  # customer org CRUD
│   └── redis_sync.rs     # Redis write + pubsub publish
├── static/               # built Svelte SPA (gitignored)
└── frontend/             # Svelte project
    ├── package.json
    ├── vite.config.ts
    ├── src/
    │   ├── App.svelte
    │   ├── lib/
    │   │   ├── api.ts        # API client
    │   │   ├── auth.ts       # auth store
    │   │   └── types.ts      # TypeScript types
    │   └── routes/
    │       ├── Login.svelte
    │       ├── Signup.svelte
    │       └── Dashboard.svelte
    └── index.html
```

## [S12] Dependencies

### Rust (dashboard crate)
- axum, tower, tower-http
- sqlx (with postgres, runtime-tokio)
- serde, serde_json
- bcrypt
- jsonwebtoken
- redis (tokio-comp)
- dotenvy
- uuid
- tracing, tracing-subscriber

### Frontend
- svelte, svelte-spa-router (or svelte-routing)
- vite, @sveltejs/vite-plugin-svelte
