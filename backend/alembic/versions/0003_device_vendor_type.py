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


def upgrade() -> None:
    op.add_column("firewall_device", sa.Column("vendor_type", sa.String(length=20), nullable=True))


def downgrade() -> None:
    op.drop_column("firewall_device", "vendor_type")
