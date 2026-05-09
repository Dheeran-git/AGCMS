import os

import databases
import sqlalchemy

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://agcms:secret@localhost:5432/agcms"
)

database = databases.Database(DATABASE_URL)

metadata = sqlalchemy.MetaData()

# ------------------------------------------------------------------
# Table definitions (mirror database/init.sql)
# ------------------------------------------------------------------

tenants = sqlalchemy.Table(
    "tenants",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.String(32), primary_key=True),
    sqlalchemy.Column("name", sqlalchemy.String(256), nullable=False),
    sqlalchemy.Column("plan", sqlalchemy.String(32), nullable=False),
    sqlalchemy.Column("admin_email", sqlalchemy.String(256), nullable=False),
    sqlalchemy.Column("api_key_hash", sqlalchemy.String(64), nullable=False, unique=True),
    sqlalchemy.Column("is_active", sqlalchemy.Boolean, nullable=False, default=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("NOW()")),
    sqlalchemy.Column("settings", sqlalchemy.JSON, nullable=False, server_default=sqlalchemy.text("'{}'")),
)

tenant_users = sqlalchemy.Table(
    "tenant_users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.dialects.postgresql.UUID, primary_key=True, server_default=sqlalchemy.text("gen_random_uuid()")),
    sqlalchemy.Column("tenant_id", sqlalchemy.String(32), sqlalchemy.ForeignKey("tenants.id"), nullable=False),
    sqlalchemy.Column("external_id", sqlalchemy.String(256), nullable=False),
    sqlalchemy.Column("email", sqlalchemy.String(256)),
    sqlalchemy.Column("department", sqlalchemy.String(128)),
    sqlalchemy.Column("role", sqlalchemy.String(32), nullable=False),
    sqlalchemy.Column("is_active", sqlalchemy.Boolean, nullable=False, default=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("NOW()")),
    sqlalchemy.UniqueConstraint("tenant_id", "external_id"),
)

policies = sqlalchemy.Table(
    "policies",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.dialects.postgresql.UUID, primary_key=True, server_default=sqlalchemy.text("gen_random_uuid()")),
    sqlalchemy.Column("tenant_id", sqlalchemy.String(32), sqlalchemy.ForeignKey("tenants.id"), nullable=False),
    sqlalchemy.Column("config", sqlalchemy.JSON, nullable=False),
    sqlalchemy.Column("version", sqlalchemy.String(16), nullable=False),
    sqlalchemy.Column("is_active", sqlalchemy.Boolean, nullable=False, default=True),
    sqlalchemy.Column("created_by", sqlalchemy.dialects.postgresql.UUID, sqlalchemy.ForeignKey("tenant_users.id")),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("NOW()")),
    sqlalchemy.Column("notes", sqlalchemy.Text),
)

audit_logs = sqlalchemy.Table(
    "audit_logs",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.dialects.postgresql.UUID, server_default=sqlalchemy.text("gen_random_uuid()")),
    sqlalchemy.Column("interaction_id", sqlalchemy.dialects.postgresql.UUID, nullable=False),
    sqlalchemy.Column("tenant_id", sqlalchemy.String(32), nullable=False),
    sqlalchemy.Column("user_id", sqlalchemy.String(256), nullable=False),
    sqlalchemy.Column("department", sqlalchemy.String(128)),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime(timezone=True), nullable=False, server_default=sqlalchemy.text("NOW()")),
    sqlalchemy.Column("llm_provider", sqlalchemy.String(64), nullable=False),
    sqlalchemy.Column("llm_model", sqlalchemy.String(128)),
    sqlalchemy.Column("prompt_hash", sqlalchemy.String(64), nullable=False),
    sqlalchemy.Column("sanitized_hash", sqlalchemy.String(64)),
    sqlalchemy.Column("pii_detected", sqlalchemy.Boolean, nullable=False, default=False),
    sqlalchemy.Column("pii_entity_types", sqlalchemy.dialects.postgresql.ARRAY(sqlalchemy.Text)),
    sqlalchemy.Column("pii_risk_level", sqlalchemy.String(16)),
    sqlalchemy.Column("injection_score", sqlalchemy.Numeric(4, 3)),
    sqlalchemy.Column("injection_type", sqlalchemy.String(32)),
    sqlalchemy.Column("enforcement_action", sqlalchemy.String(16), nullable=False),
    sqlalchemy.Column("enforcement_reason", sqlalchemy.Text),
    sqlalchemy.Column("triggered_policies", sqlalchemy.dialects.postgresql.ARRAY(sqlalchemy.Text)),
    sqlalchemy.Column("response_violated", sqlalchemy.Boolean, default=False),
    sqlalchemy.Column("response_violations", sqlalchemy.JSON),
    sqlalchemy.Column("total_latency_ms", sqlalchemy.Integer),
    sqlalchemy.Column("pii_latency_ms", sqlalchemy.Integer),
    sqlalchemy.Column("injection_latency_ms", sqlalchemy.Integer),
    sqlalchemy.Column("response_latency_ms", sqlalchemy.Integer),
    sqlalchemy.Column("llm_latency_ms", sqlalchemy.Integer),
    sqlalchemy.Column("log_signature", sqlalchemy.String(64), nullable=False),
    sqlalchemy.Column("schema_version", sqlalchemy.String(8), nullable=False, server_default=sqlalchemy.text("'2.0'")),
    # Phase 5.1 — hash chain columns
    sqlalchemy.Column("previous_log_hash", sqlalchemy.String(64)),
    sqlalchemy.Column("sequence_number", sqlalchemy.BigInteger, nullable=False, server_default=sqlalchemy.text("0")),
    sqlalchemy.Column("signing_key_id", sqlalchemy.String(32), nullable=False, server_default=sqlalchemy.text("'v1'")),
)

signing_keys = sqlalchemy.Table(
    "signing_keys",
    metadata,
    sqlalchemy.Column("kid", sqlalchemy.String(32), primary_key=True),
    sqlalchemy.Column("purpose", sqlalchemy.String(16), nullable=False),
    sqlalchemy.Column("key_hash", sqlalchemy.String(64)),
    sqlalchemy.Column("is_active", sqlalchemy.Boolean, nullable=False, default=True),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("NOW()")),
    sqlalchemy.Column("retired_at", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("notes", sqlalchemy.Text),
)

chain_heads = sqlalchemy.Table(
    "chain_heads",
    metadata,
    sqlalchemy.Column("tenant_id", sqlalchemy.String(32), sqlalchemy.ForeignKey("tenants.id"), primary_key=True),
    sqlalchemy.Column("last_sequence_number", sqlalchemy.BigInteger, nullable=False, server_default=sqlalchemy.text("0")),
    sqlalchemy.Column("last_log_signature", sqlalchemy.String(64)),
    sqlalchemy.Column("last_row_created_at", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("updated_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("NOW()")),
)

audit_roots = sqlalchemy.Table(
    "audit_roots",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.dialects.postgresql.UUID, primary_key=True, server_default=sqlalchemy.text("gen_random_uuid()")),
    sqlalchemy.Column("tenant_id", sqlalchemy.String(32), sqlalchemy.ForeignKey("tenants.id"), nullable=False),
    sqlalchemy.Column("period_start", sqlalchemy.DateTime(timezone=True), nullable=False),
    sqlalchemy.Column("period_end", sqlalchemy.DateTime(timezone=True), nullable=False),
    sqlalchemy.Column("row_count", sqlalchemy.BigInteger, nullable=False),
    sqlalchemy.Column("first_sequence_number", sqlalchemy.BigInteger, nullable=False),
    sqlalchemy.Column("last_sequence_number", sqlalchemy.BigInteger, nullable=False),
    sqlalchemy.Column("merkle_root", sqlalchemy.String(64), nullable=False),
    sqlalchemy.Column("signed_root", sqlalchemy.String(64), nullable=False),
    sqlalchemy.Column("anchor_key_id", sqlalchemy.String(32), sqlalchemy.ForeignKey("signing_keys.kid"), nullable=False),
    sqlalchemy.Column("s3_url", sqlalchemy.Text),
    sqlalchemy.Column("s3_object_version", sqlalchemy.Text),
    sqlalchemy.Column("retention_until", sqlalchemy.DateTime(timezone=True), nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("NOW()")),
)

escalations = sqlalchemy.Table(
    "escalations",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.dialects.postgresql.UUID, primary_key=True, server_default=sqlalchemy.text("gen_random_uuid()")),
    sqlalchemy.Column("interaction_id", sqlalchemy.dialects.postgresql.UUID, nullable=False),
    sqlalchemy.Column("tenant_id", sqlalchemy.String(32), sqlalchemy.ForeignKey("tenants.id"), nullable=False),
    sqlalchemy.Column("created_at", sqlalchemy.DateTime(timezone=True), server_default=sqlalchemy.text("NOW()")),
    sqlalchemy.Column("reason", sqlalchemy.Text, nullable=False),
    sqlalchemy.Column("status", sqlalchemy.String(16), nullable=False, server_default=sqlalchemy.text("'PENDING'")),
    sqlalchemy.Column("reviewed_by", sqlalchemy.dialects.postgresql.UUID, sqlalchemy.ForeignKey("tenant_users.id")),
    sqlalchemy.Column("reviewed_at", sqlalchemy.DateTime(timezone=True)),
    sqlalchemy.Column("notes", sqlalchemy.Text),
)
