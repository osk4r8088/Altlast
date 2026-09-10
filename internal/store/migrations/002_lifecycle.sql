-- Adds support lifecycle, and the resolved version.
--
-- The tag is not always the version: a container on "latest" reports its
-- version from the OCI image label instead, and version_source records
-- which of the two we used.

ALTER TABLE observations ADD COLUMN version TEXT;
ALTER TABLE observations ADD COLUMN version_source TEXT;

ALTER TABLE observations ADD COLUMN support_state TEXT;
ALTER TABLE observations ADD COLUMN eol_product TEXT;
ALTER TABLE observations ADD COLUMN eol_cycle TEXT;
ALTER TABLE observations ADD COLUMN eol_date TEXT;
ALTER TABLE observations ADD COLUMN eol_days INTEGER;
ALTER TABLE observations ADD COLUMN eol_error TEXT;

CREATE INDEX IF NOT EXISTS idx_obs_support ON observations(support_state);
