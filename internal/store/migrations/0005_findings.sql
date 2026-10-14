-- What the rules found, with the evidence behind each finding.
--
-- The finding id is the engine's own: it is derived from the rule and what
-- the finding is about, so re-running the rules over a project updates each
-- finding in place instead of duplicating it — which is what lets the triage
-- state below survive a re-run.
CREATE TABLE findings (
    id             INTEGER PRIMARY KEY,
    project_id     INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    finding_id     TEXT    NOT NULL,
    rule_id        TEXT    NOT NULL,
    title          TEXT    NOT NULL,
    summary        TEXT    NOT NULL,
    description    TEXT,
    severity       TEXT    NOT NULL,
    technique      TEXT,
    technique_name TEXT,
    -- The triage state and who is on it. These belong to the analyst, so a
    -- re-run never writes them.
    status         TEXT    NOT NULL,
    assignee       TEXT,
    note           TEXT,
    src            TEXT,
    dst            TEXT,
    protocol       TEXT,
    count          INTEGER NOT NULL,
    first_seen     INTEGER NOT NULL,
    last_seen      INTEGER NOT NULL,
    -- The packet that proves it, and whatever else the rule put on the page.
    evidence       TEXT    NOT NULL,
    details        TEXT,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL,
    UNIQUE (project_id, finding_id)
);

CREATE INDEX findings_project_severity ON findings (project_id, severity);
CREATE INDEX findings_project_status ON findings (project_id, status);
CREATE INDEX findings_project_rule ON findings (project_id, rule_id);
