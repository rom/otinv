-- Initial schema: projects, captures, decoded events and the derived asset
-- inventory. Timestamps are unix nanoseconds in UTC so that capture times
-- round-trip exactly.

CREATE TABLE projects (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

CREATE TABLE captures (
    id          INTEGER PRIMARY KEY,
    project_id  INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    capture_id  TEXT    NOT NULL,
    path        TEXT    NOT NULL,
    sha256      TEXT    NOT NULL,
    bytes       INTEGER NOT NULL,
    packets     INTEGER NOT NULL,
    link_type   TEXT    NOT NULL,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    ingested_at INTEGER NOT NULL,
    -- The digest identifies a capture, so re-ingesting the same file into the
    -- same project is caught here rather than duplicating every event.
    UNIQUE (project_id, sha256)
);

CREATE TABLE events (
    id             INTEGER PRIMARY KEY,
    project_id     INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    capture_pk     INTEGER NOT NULL REFERENCES captures (id) ON DELETE CASCADE,
    capture_id     TEXT    NOT NULL,
    packet_index   INTEGER NOT NULL,
    ts             INTEGER NOT NULL,
    protocol       TEXT    NOT NULL,
    direction      TEXT    NOT NULL,
    operation      TEXT    NOT NULL,
    function_code  INTEGER NOT NULL,
    class          TEXT    NOT NULL,
    unit_id        INTEGER,
    transaction_id INTEGER,
    address        INTEGER,
    quantity       INTEGER,
    exception      TEXT,
    malformed      INTEGER NOT NULL DEFAULT 0,
    error          TEXT,
    src_mac        TEXT,
    dst_mac        TEXT,
    src_ip         TEXT    NOT NULL,
    dst_ip         TEXT    NOT NULL,
    src_port       INTEGER NOT NULL,
    dst_port       INTEGER NOT NULL,
    transport      TEXT    NOT NULL,
    vlan           TEXT,
    identity       TEXT,
    attrs          TEXT
);

CREATE INDEX events_project_ts       ON events (project_id, ts);
CREATE INDEX events_project_protocol ON events (project_id, protocol);
CREATE INDEX events_project_class    ON events (project_id, class);
CREATE INDEX events_capture          ON events (capture_pk, packet_index);

-- The inventory is derived from events and recomputed on ingest, so these
-- tables are a cache of the latest build rather than a separate source of
-- truth. User overrides will live in their own table and win over these.
CREATE TABLE assets (
    id              INTEGER PRIMARY KEY,
    project_id      INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    asset_key       TEXT    NOT NULL,
    label           TEXT    NOT NULL,
    is_gateway      INTEGER NOT NULL DEFAULT 0,
    role            TEXT    NOT NULL,
    role_confidence INTEGER NOT NULL,
    role_reasons    TEXT,
    vendor          TEXT,
    -- The distinct addresses, denormalised for the list view. The tuple
    -- history with its time ranges lives in asset_addresses.
    macs            TEXT,
    ips             TEXT,
    vlans           TEXT,
    events          INTEGER NOT NULL,
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    UNIQUE (project_id, asset_key)
);

CREATE INDEX assets_project_role ON assets (project_id, role);

CREATE TABLE asset_addresses (
    asset_pk   INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    mac        TEXT,
    ip         TEXT,
    vlan       INTEGER,
    events     INTEGER NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);

CREATE INDEX asset_addresses_asset ON asset_addresses (asset_pk);
CREATE INDEX asset_addresses_ip    ON asset_addresses (ip);

CREATE TABLE asset_attributes (
    asset_pk   INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    field      TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    confidence INTEGER NOT NULL,
    source     TEXT    NOT NULL,
    evidence   TEXT    NOT NULL
);

CREATE INDEX asset_attributes_asset ON asset_attributes (asset_pk);

CREATE TABLE asset_protocols (
    asset_pk   INTEGER NOT NULL REFERENCES assets (id) ON DELETE CASCADE,
    protocol   TEXT    NOT NULL,
    side       TEXT    NOT NULL,
    events     INTEGER NOT NULL,
    classes    TEXT,
    unit_ids   TEXT,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL
);

CREATE INDEX asset_protocols_asset ON asset_protocols (asset_pk);
