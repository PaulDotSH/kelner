-- Performance indexes: the dashboard (files_for_user), the 60s sweeper, and
-- the admin user list were doing full table scans on every run.
CREATE INDEX idx_files_owner_created ON files(owner_id, created_at DESC);
CREATE INDEX idx_files_expires ON files(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_sessions_expires ON sessions(expires_at);