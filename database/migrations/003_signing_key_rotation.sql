-- Migration 003 — Signing-key rotation workflow (Phase 5.5)
--
-- Adds a dual-approval state machine for rotating row/anchor signing keys.
-- Key material is never stored here — only the kid + a SHA-256 fingerprint
-- (key_hash) for later cross-checking with the env-var secret store.
--
-- Flow:
--   admin A proposes rotation  →  state = 'proposed'
--   admin B approves           →  state = 'approved'
--   operator updates env + restarts services + calls execute
--                              →  state = 'executed'
--                                 old kid marked retired, new kid marked active
--
-- Either state can transition to 'cancelled' at any time pre-execute.
-- Executed rows are immutable — audit record of the rotation.

BEGIN;

CREATE TABLE signing_key_rotations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    purpose         VARCHAR(16) NOT NULL CHECK (purpose IN ('row', 'anchor')),
    new_kid         VARCHAR(32) NOT NULL,
    new_key_hash    CHAR(64)    NOT NULL,
    old_kid         VARCHAR(32) NOT NULL,  -- kid active at propose time
    state           VARCHAR(16) NOT NULL DEFAULT 'proposed'
                    CHECK (state IN ('proposed', 'approved', 'executed', 'cancelled')),
    proposed_by     VARCHAR(64) NOT NULL,
    approved_by     VARCHAR(64),
    executed_by     VARCHAR(64),
    cancelled_by    VARCHAR(64),
    reason          TEXT NOT NULL,
    proposed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at     TIMESTAMPTZ,
    executed_at     TIMESTAMPTZ,
    cancelled_at    TIMESTAMPTZ
);

-- Prevent two simultaneous open rotations for the same purpose — one at a time.
CREATE UNIQUE INDEX idx_signing_key_rotations_one_open_per_purpose
    ON signing_key_rotations (purpose)
    WHERE state IN ('proposed', 'approved');

CREATE INDEX idx_signing_key_rotations_state_proposed_at
    ON signing_key_rotations (state, proposed_at DESC);

COMMIT;
