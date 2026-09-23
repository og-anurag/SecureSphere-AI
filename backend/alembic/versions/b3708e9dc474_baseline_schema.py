"""baseline schema

Revision ID: b3708e9dc474
Revises:
Create Date: 2026-09-23
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "b3708e9dc474"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the initial SecureSphere database schema."""

    op.create_table(
        "users",
        sa.Column(
            "id",
            sa.Integer(),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "username",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "email",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "password",
            sa.String(length=255),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "email",
            name="uq_users_email",
        ),
    )

    op.create_index(
        "ix_users_id",
        "users",
        ["id"],
        unique=False,
    )

    op.create_index(
        "ix_users_email",
        "users",
        ["email"],
        unique=True,
    )

    op.create_table(
        "scan_history",
        sa.Column(
            "id",
            sa.Integer(),
            primary_key=True,
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "input_type",
            sa.String(length=20),
            nullable=False,
        ),
        sa.Column(
            "target",
            sa.String(length=500),
            nullable=False,
        ),
        sa.Column(
            "risk",
            sa.String(length=20),
            nullable=False,
        ),
        sa.Column(
            "score",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "reasons",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_scan_history_user_id_users",
        ),
    )

    op.create_index(
        "ix_scan_history_id",
        "scan_history",
        ["id"],
        unique=False,
    )

    op.create_index(
        "ix_scan_history_user_id",
        "scan_history",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    """Remove the initial SecureSphere database schema."""

    op.drop_index(
        "ix_scan_history_user_id",
        table_name="scan_history",
    )

    op.drop_index(
        "ix_scan_history_id",
        table_name="scan_history",
    )

    op.drop_table("scan_history")

    op.drop_index(
        "ix_users_email",
        table_name="users",
    )

    op.drop_index(
        "ix_users_id",
        table_name="users",
    )

    op.drop_table("users")