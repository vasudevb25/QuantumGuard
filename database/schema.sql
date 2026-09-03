CREATE TABLE raw_events(
    sequence BIGINT PRIMARY KEY,
    timestamp BIGINT NOT NULL,
    pid INT,
    uid INT,
    comm TEXT,
    filename TEXT,
    event_type INT
);

CREATE TABLE cca_attestation(
    id SERIAL PRIMARY KEY,
    checked_at TIMESTAMP DEFAULT now(),
    expected BIGINT,
    received BIGINT,
    complete BOOLEAN,
    missing_sequences JSONB
);