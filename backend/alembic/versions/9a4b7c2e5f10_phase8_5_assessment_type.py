"""Phase 8.5 assessment taxonomy

Adds the Phase 8.5 product taxonomy + authorization-audit columns to ``scans``:

  * ``assessment_type``               -- "world_monitor" | "custom_target"
  * ``authorization_acknowledged``    -- operator assertion (audit record only)
  * ``authorization_acknowledged_at`` -- when the assertion was made

All columns are additive and nullable; nothing is dropped, renamed or
rewritten.  Existing rows are backfilled deterministically: any assessment whose
persisted configuration references a World Monitor deployment becomes
``world_monitor``, everything else becomes ``custom_target``.  The server-side
scope guard remains the actual authorization control; this flag is only an
audit record.

Revision ID: 9a4b7c2e5f10
Revises: 3d7f5bc81a02
Create Date: 2026-09-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9a4b7c2e5f10'
down_revision: Union[str, Sequence[str], None] = '3d7f5bc81a02'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('scans', sa.Column('assessment_type', sa.String(length=50), nullable=True))
    op.add_column('scans', sa.Column('authorization_acknowledged', sa.Boolean(), nullable=True))
    op.add_column('scans', sa.Column('authorization_acknowledged_at', sa.DateTime(), nullable=True))
    op.create_index('ix_scans_assessment_type', 'scans', ['assessment_type'])

    # Backfill: default everything to the custom-target path, then promote the
    # rows that actually reference a World Monitor deployment.
    op.execute("UPDATE scans SET assessment_type = 'custom_target' WHERE assessment_type IS NULL")

    bind = op.get_bind()
    dialect = bind.dialect.name
    if dialect == 'sqlite':
        op.execute(
            "UPDATE scans SET assessment_type = 'world_monitor' "
            "WHERE scan_config LIKE '%world_monitor%'"
        )
    elif dialect == 'postgresql':
        op.execute(
            "UPDATE scans SET assessment_type = 'world_monitor' "
            "WHERE scan_config::text LIKE '%world_monitor%'"
        )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_scans_assessment_type', table_name='scans')
    op.drop_column('scans', 'authorization_acknowledged_at')
    op.drop_column('scans', 'authorization_acknowledged')
    op.drop_column('scans', 'assessment_type')
