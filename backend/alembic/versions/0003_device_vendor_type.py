"""Add firewall_device.vendor_type

Adds the semantic connector vendor_type ('fortinet' | 'paloalto') to
firewall_device (V3 Table 8), used by the acquisition connector registry. Nullable
so legacy rows are unaffected; the app derives it from the vendor when absent.

Revision ID: 0003_device_vendor_type
Revises: 0002_rule_service_mapping
Create Date: 2026-06-22
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_device_vendor_type"
down_revision: Union[str, None] = "0002_rule_service_mapping"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(bind, table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(bind).get_columns(table)}


def upgrade() -> None:
    # Idempotent: the 0001 baseline create_all already adds this column from the
    # current model metadata. Skip if present.
    bind = op.get_bind()
    if _has_column(bind, "firewall_device", "vendor_type"):
        return
    op.add_column("firewall_device", sa.Column("vendor_type", sa.String(length=20), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind, "firewall_device", "vendor_type"):
        return
    op.drop_column("firewall_device", "vendor_type")
