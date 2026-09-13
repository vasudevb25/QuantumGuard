-- QuantumGuard - full schema (Phases 1, 2, 4 and 5).
--
-- Every statement is IF NOT EXISTS, so this file is safe to run more
-- than once against the same database (e.g. after pulling in a change
-- here) without dropping or erroring on tables that already hold
-- captured evidence.
--
--   sudo -u postgres psql -d provenance -f database/schema.sql
--   sudo -u postgres psql -d provenance -c \
--     "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO quantumguard; \
--      GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO quantumguard;"


-- ---------------------------------------------------------------
-- Phase 1/2 - raw capture and completeness attestation
-- ---------------------------------------------------------------
-- One row per captured execve event, and one row per CCA gap (only
-- incomplete attestations are stored - core/store.py.save_attestation()
-- skips writing anything when a sequence arrived exactly as expected).

CREATE TABLE IF NOT EXISTS raw_events (
    sequence    BIGINT      PRIMARY KEY,
    timestamp   BIGINT      NOT NULL,
    pid         INT,
    uid         INT,
    comm        TEXT,
    filename    TEXT,
    event_type  INT
);

CREATE TABLE IF NOT EXISTS cca_attestation (
    id                  SERIAL      PRIMARY KEY,
    checked_at          TIMESTAMP   DEFAULT now(),
    expected            BIGINT,
    received            BIGINT,
    complete            BOOLEAN,
    missing_sequences   JSONB
);


-- ---------------------------------------------------------------
-- Phase 5 - sealed evidence partitions
-- ---------------------------------------------------------------
-- One row per Merkle-sealed slice of the provenance graph.
-- prev_record_hash chains the rows together, so deleting a whole row is
-- detectable; record_hash is what both signatures are computed over.

CREATE TABLE IF NOT EXISTS graph_partitions (
    id                  BIGSERIAL   PRIMARY KEY,
    run_id              TEXT        NOT NULL,
    partition_index     INT         NOT NULL,

    seq_start           BIGINT      NOT NULL,
    seq_end             BIGINT      NOT NULL,
    leaf_count          INT         NOT NULL,

    merkle_root         TEXT        NOT NULL,
    prev_record_hash    TEXT        NOT NULL,
    record_hash         TEXT        NOT NULL,

    -- placeholder for Phase 6 risk-adaptive anchoring
    risk_tier_hint      TEXT        DEFAULT 'tier3_local',

    ed25519_public_key  TEXT        NOT NULL,
    ed25519_signature   TEXT        NOT NULL,

    mldsa_algorithm     TEXT        NOT NULL,
    mldsa_public_key    TEXT        NOT NULL,
    mldsa_signature     TEXT        NOT NULL,

    leaf_hashes         JSONB       NOT NULL,
    created_at          TEXT        NOT NULL,

    UNIQUE (run_id, partition_index)
);

CREATE INDEX IF NOT EXISTS idx_partitions_run  ON graph_partitions (run_id);
CREATE INDEX IF NOT EXISTS idx_partitions_seq  ON graph_partitions (seq_start, seq_end);
CREATE INDEX IF NOT EXISTS idx_partitions_tier ON graph_partitions (risk_tier_hint);


-- ---------------------------------------------------------------
-- Phase 4 - poisoning detection reports
-- ---------------------------------------------------------------
-- A detection report is itself evidence: it is the record that says
-- "tampering was found, here is why". Phase 5 seals these too, which is
-- what stops an attacker from quietly deleting the alert.

CREATE TABLE IF NOT EXISTS detection_reports (
    id                    BIGSERIAL   PRIMARY KEY,
    run_id                TEXT,
    created_at            TEXT        NOT NULL,

    tampered              BOOLEAN     NOT NULL,
    rule_violation_count  INT         NOT NULL DEFAULT 0,
    gnn_flagged_nodes     INT         NOT NULL DEFAULT 0,

    graph_nodes           INT,
    graph_edges           INT,

    detail                JSONB
);

CREATE INDEX IF NOT EXISTS idx_reports_run      ON detection_reports (run_id);
CREATE INDEX IF NOT EXISTS idx_reports_tampered ON detection_reports (tampered);


-- ---------------------------------------------------------------
-- Optional: capture-session continuity (see README's Known limitations)
-- ---------------------------------------------------------------
-- The collector resets its sequence counter to 1 on restart, so a
-- session identifier is needed before completeness can be attested
-- across runs. The table is created here; wiring a run_id through
-- capture/collector.py and graph/service.py is a separate change and is
-- deliberately NOT done by this file.

CREATE TABLE IF NOT EXISTS capture_sessions (
    run_id          TEXT        PRIMARY KEY,
    host            TEXT,
    started_at      TIMESTAMP   DEFAULT now(),
    ended_at        TIMESTAMP,
    last_sequence   BIGINT
);
