-- Mutes: a finding you have judged and accepted.
--
-- Both a reason and an expiry are required. A mute without a reason
-- becomes an unexplained silence nobody dares remove in a year; a mute
-- without an expiry becomes permanent by accident. Requiring both makes a
-- mute a decision with a review date.
--
-- Identity matches the finding: (asset, type, key). Muting EOL on
-- Postgres cycle 13 does not mute it on cycle 14, so upgrading into a new
-- unsupported cycle still tells you.

CREATE TABLE IF NOT EXISTS mutes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    type TEXT NOT NULL,
    key  TEXT NOT NULL DEFAULT '',

    reason     TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,

    -- Set when a scan first observes that the mute has lapsed, so the
    -- expiry can be reported once rather than on every scan afterwards.
    expiry_reported_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mutes_identity
    ON mutes(asset_id, type, key);