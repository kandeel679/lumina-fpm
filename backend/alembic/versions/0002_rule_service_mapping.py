"""Add rule_service_mapping table

Incremental revision adding the rule_service_mapping table (rule ↔ service
correlation, mirroring rule_object_mapping for the service axis). Either
service_object_id (vendor-owned) or normalized_service_id (canonical) may be set.

Revision ID: 0002_rule_service_mapping
Revises: 0001_schema_v4_baseline
Create Date: 2026-06-22
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_rule_service_mapping"
down_revision: Union[str, None] = "0001_schema_v4_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # The 0001 baseline builds the schema from live model metadata (create_all),
    # which already includes this table. Guard so the chain is idempotent on a
    # fresh DB while remaining a real migration for older DBs.
    bind = op.get_bind()
    if "rule_service_mapping" in sa.inspect(bind).get_table_names():
        return
    op.create_table(
        "rule_service_mapping",
        sa.Column("mapping_id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("rule_id", sa.Integer(), nullable=False),
        sa.Column("service_object_id", sa.Integer(), nullable=True),
        sa.Column("normalized_service_id", sa.Integer(), nullable=True),
        sa.Column("mapping_type", sa.String(length=50), server_default="service", nullable=False),
        sa.Column("direction", sa.String(length=20), server_default="service", nullable=False),
        sa.ForeignKeyConstraint(["rule_id"], ["policy_rule.rule_id"]),
        sa.ForeignKeyConstraint(["service_object_id"], ["service_object.service_object_id"]),
        sa.ForeignKeyConstraint(
            ["normalized_service_id"], ["normalized_service.normalized_service_id"]
        ),
        sa.PrimaryKeyConstraint("mapping_id"),
    )
    op.create_index("idx_rulesvcmap_rule", "rule_service_mapping", ["rule_id"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    if "rule_service_mapping" not in sa.inspect(bind).get_table_names():
        return
    op.drop_index("idx_rulesvcmap_rule", table_name="rule_service_mapping")
    op.drop_table("rule_service_mapping")
