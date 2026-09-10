-- A higher major line that exists upstream but is not comparable to the
-- running tag. Recorded so the dashboard can warn without recommending.
ALTER TABLE observations ADD COLUMN newer_major INTEGER;
ALTER TABLE observations ADD COLUMN newer_major_tag TEXT;
