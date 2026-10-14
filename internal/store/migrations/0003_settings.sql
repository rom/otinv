-- GUI settings, stored per project because the GUI has no user accounts yet.
-- When accounts arrive, a user_id column joins the key and the per-user value
-- wins over the project-wide one.
CREATE TABLE settings (
    project_id INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    key        TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (project_id, key)
);
