-- JUSeeds initial schema. Intended for a new database. Back up and review any existing database first.
CREATE TABLE IF NOT EXISTS schools (
 id BIGSERIAL PRIMARY KEY, name TEXT NOT NULL, code TEXT NOT NULL UNIQUE,
 description TEXT NOT NULL DEFAULT '', active BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS teams (
 id BIGSERIAL PRIMARY KEY, school_id BIGINT NOT NULL REFERENCES schools(id) ON DELETE RESTRICT,
 name TEXT NOT NULL, code TEXT NOT NULL, active BOOLEAN NOT NULL DEFAULT TRUE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 UNIQUE(school_id,code), UNIQUE(school_id,name)
);
CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 full_name TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','in_charge','school_user')),
 school_id BIGINT REFERENCES schools(id) ON DELETE RESTRICT, team_id BIGINT REFERENCES teams(id) ON DELETE RESTRICT,
 active BOOLEAN NOT NULL DEFAULT TRUE, must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 CHECK(username=LOWER(username)), CHECK(role='admin' OR school_id IS NOT NULL),
 CHECK(role<>'school_user' OR team_id IS NOT NULL)
);
CREATE TABLE IF NOT EXISTS in_charge_assignments (
 id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 school_id BIGINT NOT NULL REFERENCES schools(id) ON DELETE RESTRICT,
 team_id BIGINT REFERENCES teams(id) ON DELETE RESTRICT, assigned_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
 active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_assignments_user_active ON in_charge_assignments(user_id,active);
CREATE TABLE IF NOT EXISTS visit_reference_counter(id BIGSERIAL PRIMARY KEY,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS visit_plans (
 id BIGSERIAL PRIMARY KEY, reference_number TEXT NOT NULL UNIQUE,
 created_by BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 school_id BIGINT NOT NULL REFERENCES schools(id) ON DELETE RESTRICT,
 team_id BIGINT NOT NULL REFERENCES teams(id) ON DELETE RESTRICT,
 title TEXT NOT NULL, destination TEXT NOT NULL DEFAULT '', destination_address TEXT NOT NULL DEFAULT '',
 contact_info TEXT NOT NULL DEFAULT '', visit_date DATE, start_time TIME, end_time TIME,
 transport_method TEXT NOT NULL DEFAULT '', purpose TEXT NOT NULL DEFAULT '', objectives TEXT NOT NULL DEFAULT '',
 participants TEXT NOT NULL DEFAULT '', requirements TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','pending','approved','rejected','completed','report_submitted','report_accepted')),
 submitted_at TIMESTAMPTZ, completed_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CHECK(end_time IS NULL OR start_time IS NULL OR end_time>start_time)
);
CREATE INDEX IF NOT EXISTS idx_visits_creator ON visit_plans(created_by,updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_visits_scope_status ON visit_plans(school_id,team_id,status,visit_date);
CREATE TABLE IF NOT EXISTS visit_reviews (
 id BIGSERIAL PRIMARY KEY, visit_plan_id BIGINT NOT NULL REFERENCES visit_plans(id) ON DELETE RESTRICT,
 reviewer_id BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 decision TEXT NOT NULL CHECK(decision IN ('approved','rejected','correction_requested','report_accepted','report_correction_requested')),
 remarks TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_reviews_visit ON visit_reviews(visit_plan_id,created_at);
CREATE TABLE IF NOT EXISTS visit_reports (
 id BIGSERIAL PRIMARY KEY, visit_plan_id BIGINT NOT NULL UNIQUE REFERENCES visit_plans(id) ON DELETE RESTRICT,
 submitted_by BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT, report_content JSONB NOT NULL DEFAULT '{}'::jsonb,
 status TEXT NOT NULL DEFAULT 'submitted' CHECK(status IN ('submitted','correction_requested','accepted')),
 submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), reviewed_by BIGINT REFERENCES users(id) ON DELETE RESTRICT,
 reviewed_at TIMESTAMPTZ, review_remarks TEXT NOT NULL DEFAULT '',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS documents (
 id BIGSERIAL PRIMARY KEY, visit_plan_id BIGINT NOT NULL REFERENCES visit_plans(id) ON DELETE RESTRICT,
 visit_report_id BIGINT REFERENCES visit_reports(id) ON DELETE RESTRICT,
 uploaded_by BIGINT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 storage_key TEXT NOT NULL, original_filename TEXT NOT NULL, mime_type TEXT NOT NULL,
 size_bytes BIGINT NOT NULL CHECK(size_bytes>=0), document_type TEXT NOT NULL DEFAULT 'evidence',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_documents_visit ON documents(visit_plan_id);
CREATE TABLE IF NOT EXISTS app_sessions (
 id TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON app_sessions(expires_at);
CREATE TABLE IF NOT EXISTS audit_logs (
 id BIGSERIAL PRIMARY KEY, actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
 action TEXT NOT NULL, entity_type TEXT NOT NULL, entity_id TEXT,
 metadata JSONB NOT NULL DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);

CREATE TABLE IF NOT EXISTS login_attempts (
 id BIGSERIAL PRIMARY KEY,
 username TEXT NOT NULL,
 ip_address TEXT NOT NULL,
 attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_window ON login_attempts(username,ip_address,attempted_at DESC);
