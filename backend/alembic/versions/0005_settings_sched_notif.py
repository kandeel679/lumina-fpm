"""Settings, scheduling & notifications

Adds the tables/columns behind the editable Settings page:
  - firewall_device.use_http  : per-device lab override to force plain HTTP API calls.
  - schedule_config           : user-configurable schedules for acquisition / detection /
                                threat-intel (driven by the Celery Beat 'scheduler.tick').
  - notification              : in-app notifications written by the background pipeline.

Idempotent: the 0001 baseline create_all already materialises any table currently in
the model metadata, so a FRESH database has these objects after 0001 — each step is
skipped if the column/table is already present. On a database already at 0004 the
objects do not exist yet, so they are created here.

Revision ID: 0005_settings_sched_notif
Revises: 0004_llm_report_document
Create Date: 2026-06-27

(Revision id kept <=32 chars to fit alembic_version.version_num VARCHAR(32).)
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005_settings_sched_notif"
down_revision: Union[str, None] = "0004_llm_report_document"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _has_table(bind, table: str) -> bool:
    return sa.inspect(bind).has_table(table)


def _has_column(bind, table: str, column: str) -> bool:
    if not _has_table(bind, table):
        return False
    return column in {c["name"] for c in sa.inspect(bind).get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()

    # 1) firewall_device.use_http -----------------------------------------------------
    if not _has_column(bind, "firewall_device", "use_http"):
        op.add_column(
            "firewall_device",
            sa.Column("use_http", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )

    # 2) schedule_config --------------------------------------------------------------
    if not _has_table(bind, "schedule_config"):
        op.create_table(
            "schedule_config",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("operation", sa.String(length=30), nullable=False, unique=True),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("mode", sa.String(length=10), nullable=False, server_default=sa.text("'interval'")),
            sa.Column("interval_minutes", sa.Integer(), nullable=True),
            sa.Column("cron_expression", sa.String(length=120), nullable=True),
            sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )

    # 3) notification -----------------------------------------------------------------
    if not _has_table(bind, "notification"):
        op.create_table(
            "notification",
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("level", sa.String(length=12), nullable=False, server_default=sa.text("'info'")),
            sa.Column("category", sa.String(length=20), nullable=False, server_default=sa.text("'system'")),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("body", sa.Text(), nullable=True),
            sa.Column("link", sa.String(length=120), nullable=True),
            sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("idx_notification_created", "notification", ["created_at"])
        op.create_index("idx_notification_read", "notification", ["read_at"])


def downgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "notification"):
        op.drop_index("idx_notification_read", table_name="notification")
        op.drop_index("idx_notification_created", table_name="notification")
        op.drop_table("notification")
    if _has_table(bind, "schedule_config"):
        op.drop_table("schedule_config")
    if _has_column(bind, "firewall_device", "use_http"):
        op.drop_column("firewall_device", "use_http")
