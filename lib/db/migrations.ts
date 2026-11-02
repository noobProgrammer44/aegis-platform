/**
 * Schema migrations, applied in order and tracked with `PRAGMA user_version`.
 * Append new migrations; never edit one that has shipped.
 */
export const MIGRATIONS: readonly string[] = [
  `
  CREATE TABLE workspaces (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE targets (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    kind TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    tags TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL DEFAULT 'manual',
    health_score INTEGER NOT NULL DEFAULT 0,
    health_grade TEXT NOT NULL DEFAULT 'A',
    last_scanned_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, target)
  );

  CREATE TABLE discovered_domains (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    via_target_id TEXT REFERENCES targets(id) ON DELETE SET NULL,
    via_target TEXT,
    resolves INTEGER NOT NULL DEFAULT 0,
    records TEXT NOT NULL DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    promoted_target_id TEXT REFERENCES targets(id) ON DELETE SET NULL,
    UNIQUE (workspace_id, name)
  );

  CREATE TABLE authorizations (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    method TEXT NOT NULL,
    token TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    attested_by TEXT,
    note TEXT,
    created_at TEXT NOT NULL,
    verified_at TEXT,
    UNIQUE (workspace_id, scope, method)
  );

  CREATE TABLE audit_log (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT '{}'
  );
  CREATE INDEX audit_log_ws_at ON audit_log (workspace_id, at DESC);

  CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    state TEXT NOT NULL,
    progress INTEGER NOT NULL DEFAULT 0,
    progress_message TEXT,
    target_ids TEXT NOT NULL DEFAULT '[]',
    targets TEXT NOT NULL DEFAULT '[]',
    skipped_targets TEXT NOT NULL DEFAULT '[]',
    risks TEXT NOT NULL DEFAULT '{"newOpen":0,"stillOpen":0,"closed":0}',
    scheduled_by TEXT,
    error TEXT,
    ai_summary TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
  );
  CREATE INDEX scans_ws_created ON scans (workspace_id, created_at DESC);
  CREATE INDEX scans_state ON scans (state);

  CREATE TABLE scan_results (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target_id TEXT,
    filename TEXT NOT NULL,
    content_type TEXT NOT NULL,
    content BLOB NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX scan_results_scan ON scan_results (scan_id);

  CREATE TABLE risks (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    target_id TEXT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    title TEXT NOT NULL,
    threat_level TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    solution TEXT NOT NULL DEFAULT '',
    refs TEXT NOT NULL DEFAULT '[]',
    cvss TEXT,
    additional_info TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL,
    is_accepted INTEGER NOT NULL DEFAULT 0,
    accepted_reason TEXT,
    accepted_by TEXT,
    first_detected_at TEXT NOT NULL,
    last_detected_at TEXT NOT NULL,
    closed_at TEXT,
    last_scan_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (workspace_id, target_id, fingerprint)
  );
  CREATE INDEX risks_ws_status ON risks (workspace_id, status);
  CREATE INDEX risks_target ON risks (target_id);

  CREATE TABLE acceptance_rules (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    query TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  );

  CREATE TABLE scheduled_scans (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    schedule TEXT NOT NULL,
    interval_days INTEGER,
    scan_types TEXT NOT NULL,
    targets_filter TEXT NOT NULL,
    notify_emails TEXT NOT NULL DEFAULT '[]',
    notify_policy TEXT NOT NULL DEFAULT 'ON_CHANGES',
    start_at TEXT NOT NULL,
    next_run TEXT,
    last_ran TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  );

  CREATE TABLE reports (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    format TEXT NOT NULL,
    filters TEXT NOT NULL,
    sections TEXT NOT NULL,
    scheduled_report_id TEXT,
    ai_summary TEXT,
    snapshot TEXT NOT NULL,
    created_at TEXT NOT NULL
  );

  CREATE TABLE scheduled_reports (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    format TEXT NOT NULL,
    filters TEXT NOT NULL,
    sections TEXT NOT NULL,
    schedule TEXT NOT NULL,
    interval_days INTEGER,
    emails TEXT NOT NULL DEFAULT '[]',
    start_at TEXT NOT NULL,
    next_run TEXT,
    last_ran TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  );

  CREATE TABLE webhooks (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    url TEXT NOT NULL,
    secret TEXT NOT NULL,
    events TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
  );

  CREATE TABLE webhook_deliveries (
    id TEXT PRIMARY KEY,
    webhook_id TEXT NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event TEXT NOT NULL,
    ok INTEGER NOT NULL,
    status_code INTEGER,
    error TEXT,
    at TEXT NOT NULL
  );
  CREATE INDEX webhook_deliveries_hook ON webhook_deliveries (webhook_id, at DESC);

  CREATE TABLE api_keys (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT
  );

  CREATE TABLE settings (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (workspace_id, key)
  );

  CREATE TABLE notifications (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    recipients TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    status TEXT NOT NULL,
    error TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE health_snapshots (
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    target_key TEXT NOT NULL,
    day TEXT NOT NULL,
    score INTEGER NOT NULL,
    grade TEXT NOT NULL,
    counts TEXT NOT NULL,
    assets INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (workspace_id, target_key, day)
  );
  `,
  // 2: how hard a scan hits its targets (lib/recon/intensity.ts).
  `
  ALTER TABLE scans ADD COLUMN intensity TEXT NOT NULL DEFAULT 'polite';
  `,
  // 3: scheduled scans remember their intensity too.
  `
  ALTER TABLE scheduled_scans ADD COLUMN intensity TEXT NOT NULL DEFAULT 'polite';
  `,
];
