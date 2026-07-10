---
feature: dashboard
status: delivered
specs:
  - ../specs/2025-07-07-dashboard-design.md
plans:
  - ../plans/2025-07-07-dashboard-implementation.md
branch: validate-h3-requests
commits: b7a91fc..524b08f
---

# QuicGuard Management Dashboard — Final Report

## What Was Built

A full-stack management dashboard for QuicGuard organization configurations. The system allows customers to register (pending admin approval), log in, and manage their organization configs via a web UI. Admins can approve users and view all organizations. Every config mutation (create/update/delete) syncs to Redis in real-time via HSET + PUBLISH to `quicguard:updates`, so the running QUIC server picks up changes instantly through its existing pubsub subscription.

## Architecture

```
Svelte SPA ──▶ Axum Backend ──▶ Postgres (users, orgs)
                    │
                    └──────────▶ Redis (pubsub + org configs)
```

### Backend (`dashboard/` crate)

- **Entry point:** `src/main.rs` — CLI with `run-migrations` and `create-admin` subcommands, plus the HTTP server
- **Auth:** `src/auth.rs` — bcrypt password hashing (cost 12), JWT creation/validation (HS256, 24h expiry)
- **Middleware:** `src/middleware.rs` — `auth_middleware` (validates JWT, inserts `AuthUser`), `admin_only` (adds role check)
- **Routes:** `src/routes/auth.rs` (signup, login, me), `admin.rs` (list users, approve, delete, list all orgs), `organizations.rs` (customer CRUD)
- **Redis sync:** `src/redis_sync.rs` — `sync_org_to_redis` (HSET + PUBLISH), `remove_org_from_redis` (HDEL + PUBLISH)
- **Config:** `src/config.rs` — loads from env via dotenvy
- **Database:** `src/db.rs` — sqlx Postgres pool, auto-runs migrations

### Frontend (`dashboard/frontend/`)

Svelte SPA with three routes:
- `/login` — email/password login with approval status feedback
- `/signup` — registration with redirect to login on success
- `/dashboard` — role-based: admin sees user list + approve/delete; customer sees own orgs; both get CRUD for organizations with JSON config editor

Built with Vite, output to `dashboard/static/`, served by Axum as SPA with fallback.

### Data Model

**users:** id (UUID), email (unique), password_hash, role (admin/customer), approved (boolean), timestamps

**organizations:** id (VARCHAR PK matching Redis key), owner_id (FK→users), name, config (JSONB), timestamps

### API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/signup` | None | Register (pending approval) |
| POST | `/api/auth/login` | None | Get JWT |
| GET | `/api/auth/me` | Any | Current user |
| GET | `/api/admin/users` | Admin | List users |
| PUT | `/api/admin/users/:id/approve` | Admin | Approve user |
| DELETE | `/api/admin/users/:id` | Admin | Delete user |
| GET | `/api/admin/organizations` | Admin | All orgs |
| GET | `/api/organizations` | Customer | Own orgs |
| POST | `/api/organizations` | Customer | Create org |
| PUT | `/api/organizations/:id` | Customer | Update org |
| DELETE | `/api/organizations/:id` | Customer | Delete org |

### Infrastructure

- **Docker Compose:** Postgres 16 added alongside Redis, both with resource limits
- **Setup script:** `dashboard/scripts/setup.sh` — starts services, runs migrations, creates admin, builds frontend

### Design Decisions

- **Separate crate** — kept dashboard isolated from the QUIC server and konfig crate, clean dependency boundaries
- **Middleware applied in main.rs** — axum 0.7's `from_fn` type inference fails on nested routers; applying `from_fn_with_state` at the top level after state is available resolves this
- **JSONB for org config** — mirrors the existing Redis schema exactly, making sync trivial and allowing the QUIC server's existing `OrgUpdate` format to work unchanged
- **Public signup + admin approval** — avoids the bootstrap problem of needing an admin to exist before anyone can sign up

## Usage

```bash
# Quick start
cd dashboard && bash scripts/setup.sh

# Or manually:
cd services && docker compose up -d
cd ../dashboard
cp .env.example .env
cargo build --release
./target/release/dashboard run-migrations
./target/release/dashboard create-admin admin@quicguard.local admin123
cd frontend && npm install && npm run build
cd .. && cargo run --release
```

Dashboard: http://localhost:3000

## Verification

- All Rust code compiles in both debug and release mode
- Frontend builds successfully via `npm run build`
- Docker Compose syntax is valid
- File structure verified — all modules, routes, and frontend components in place

## Journey Log

- [dead end] `middleware::from_fn` on nested routers fails type inference in axum 0.7 — the state type resolves to `()` instead of `(DbPool, Config)`. Fixed by moving middleware application to main.rs where state is explicitly provided via `from_fn_with_state`.
- [lesson] Node.js 18 is incompatible with create-vite 6+ (requires Node 20+). Used `create-vite@5` as fallback.
- [lesson] The `dashboard/static/` build output is correctly gitignored — it's a build artifact that users regenerate with `npm run build`.

## Source Materials

| File | Role | Notes |
|------|------|-------|
| `docs/compose/specs/2025-07-07-dashboard-design.md` | Design spec | Complete |
| `docs/compose/plans/2025-07-07-dashboard-implementation.md` | Implementation plan | 9 tasks, all completed |
