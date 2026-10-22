# JUSeeds

University school visit planning, approvals, reporting and evidence management.

## Current architecture
- Responsive HTML, CSS and vanilla JavaScript frontend
- Node.js Vercel serverless API
- Neon PostgreSQL through pg
- bcrypt password hashing and opaque server-managed sessions
- Roles: admin, in_charge, school_user
- SQL schema in db/schema.sql

## Required Vercel Production environment variables
- DATABASE_URL: Neon PostgreSQL connection string, server-side only
- SESSION_SECRET: random secret with at least 32 characters of entropy; generate with Node crypto
- PGSSL: optional; defaults to TLS enabled. Do not disable in production
- ADMIN_BOOTSTRAP_TOKEN: optional temporary one-time bootstrap token, at least 32 characters; remove after use

Never commit production credentials or put secrets in browser code.

## First setup
1. Create the intended Neon database and save a backup if it contains data.
2. Review db/schema.sql. It is an initial schema for a new database. Do not run it blindly over an existing production schema.
3. Apply schema.sql using Neon SQL Editor or a trusted migration runner.
4. Create the first administrator from a trusted environment:
   - Set DATABASE_URL and ADMIN_PASSWORD as environment variables.
   - Run npm install, then node scripts/create-admin.mjs.
   - The password must be unique and at least 14 characters.
   - The script refuses to overwrite an existing administrator.
5. Configure DATABASE_URL and SESSION_SECRET in Vercel Production and redeploy.
6. Test /api/health, username/password login, /api/auth/me, logout and role permissions.

The optional bootstrap endpoint is not required when using the CLI script. Do not leave a bootstrap token configured longer than necessary.

## Local development
- npm install
- npm run check
- npx vercel dev

## Important limitations in this first implementation
- Private object storage provider is not configured; evidence uploads and generated PDFs are not enabled yet.
- In-Charge assignment UI is available. The initial 9-school / 45-team structure must still be entered by an administrator; school names were not guessed or hardcoded.
- Database-backed login throttling and source syntax checks are included. End-to-end integration tests and production acceptance testing are still required.
- Review and apply database schema intentionally; deployment alone does not create database tables.
- A deployment marked READY does not prove that live login/database flows work.
