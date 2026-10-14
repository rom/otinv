-- The Purdue level an asset was placed in, with the evidence behind it.
--
-- NULL means unplaced: a forwarding device spans levels rather than sitting
-- in one, and an asset nothing was observed about sits nowhere until the
-- analyst says otherwise. Level 0 is a level, so it cannot be the default.
ALTER TABLE assets ADD COLUMN purdue_level INTEGER;
ALTER TABLE assets ADD COLUMN purdue_confidence INTEGER NOT NULL DEFAULT 0;
ALTER TABLE assets ADD COLUMN purdue_reasons TEXT;

CREATE INDEX assets_project_level ON assets (project_id, purdue_level);
