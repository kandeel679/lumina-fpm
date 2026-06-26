"""Add structured-report columns to llm_report

Adds document (JSONB), markdown (Text), and executive_summary (Text) to llm_report
so a SOC report stores its deterministic structured sections + a downloadable
Markdown render alongside the AI-authored executive summary (V10 §8). Idempotent:
the 0001 baseline create_all already adds these from the current model metadata, so
each column is skipped if present.

Revision ID: 0004_llm_report_document
Revises: 0003_device_vendor_type
Create Date: 2026-06-26
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0004_llm_report_document"
down_revision: Union[str, None] = "0003_device_vendor_type"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_column(bind, table: str, column: str) -> bool:
    return column in {c["name"] for c in sa.inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind, "llm_report", "document"):
        op.add_column("llm_report", sa.Column("document", JSONB(), nullable=True))
    if not _has_column(bind, "llm_report", "markdown"):
        op.add_column("llm_report", sa.Column("markdown", sa.Text(), nullable=True))
    if not _has_column(bind, "llm_report", "executive_summary"):
        op.add_column("llm_report", sa.Column("executive_summary", sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    for col in ("executive_summary", "markdown", "document"):
        if _has_column(bind, "llm_report", col):
            op.drop_column("llm_report", col)
