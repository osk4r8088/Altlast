-- Initial schema.
--
-- Design: snapshot per scan. Every scan writes one row per asset into
-- observations. Nothing is updated in place, so history is complete.

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    host        TEXT NOT NULL,
    asset_count INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0
);

-- Stable identity of a tracked thing, independent of any single scan.
-- A container keeps its identity across image upgrades, which is what
-- lets us see that it moved.
CREATE TABLE IF NOT EXISTS assets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host       TEXT NOT NULL,
    kind       TEXT NOT NULL,
    name       TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    UNIQUE (host, kind, name)
);

CREATE TABLE IF NOT EXISTS observations (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    registry   TEXT,
    repository TEXT,
    tag        TEXT,
    image_id   TEXT,
    digest     TEXT,
    state      TEXT,

    latest        TEXT,
    behind        INTEGER,
    comparable    INTEGER NOT NULL DEFAULT 0,
    resolve_error TEXT,

    observed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_obs_asset ON observations(asset_id, observed_at);
CREATE INDEX IF NOT EXISTS idx_obs_scan  ON observations(scan_id);
