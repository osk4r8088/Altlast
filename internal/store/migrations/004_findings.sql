-- Findings: things worth telling someone about, tracked over time.
--
-- A finding is identified by (asset_id, type, key). It opens when first
-- observed, stays open while it keeps being observed, and resolves when a
-- scan no longer produces it. That lifecycle is what makes "new since last
-- scan" and time-to-resolve possible.

CREATE TABLE IF NOT EXISTS findings (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    type     TEXT NOT NULL,
    key      TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    detail   TEXT,

    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    resolved_at TEXT,

    first_scan_id INTEGER NOT NULL REFERENCES scans(id),
    last_scan_id  INTEGER NOT NULL REFERENCES scans(id)
);

-- Only one open finding per (asset, type, key). A resolved one may sit
-- alongside it in history, which is why the constraint is partial.
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_open
    ON findings(asset_id, type, key)
    WHERE resolved_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_findings_first_scan ON findings(first_scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_open_sev
    ON findings(severity) WHERE resolved_at IS NULL;
