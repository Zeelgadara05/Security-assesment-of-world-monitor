"""scan job lifecycle

Adds the Phase 4 job-lifecycle columns to ``scans``: fine-grained stage,
structured progress metadata, the honest assessment-coverage metric, the
captured scan configuration, and cancellation/timing fields.

Revision ID: 5c1d34a9e72f
Revises: 8f3a2c51d94e6b77
Create Date: 2026-09-19 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '5c1d34a9e72f'
down_revision: Union[str, Sequence[str], None] = '8f3a2c51d94e6b77'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('scans', sa.Column('stage', sa.String(length=50), nullable=True, server_default='queued'))
    op.add_column('scans', sa.Column('progress', sa.JSON(), nullable=True))
    op.add_column('scans', sa.Column('coverage', sa.Float(), nullable=True))
    op.add_column('scans', sa.Column('scan_config', sa.JSON(), nullable=True))
    op.add_column('scans', sa.Column('cancel_requested', sa.Boolean(), nullable=True, server_default=sa.text('0')))
    op.add_column('scans', sa.Column('started_at', sa.DateTime(), nullable=True))
    op.add_column('scans', sa.Column('updated_at', sa.DateTime(), nullable=True))
    op.add_column('scans', sa.Column('cancelled_at', sa.DateTime(), nullable=True))
    op.add_column('scans', sa.Column('error', sa.Text(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scans', 'error')
    op.drop_column('scans', 'cancelled_at')
    op.drop_column('scans', 'updated_at')
    op.drop_column('scans', 'started_at')
    op.drop_column('scans', 'cancel_requested')
    op.drop_column('scans', 'scan_config')
    op.drop_column('scans', 'coverage')
    op.drop_column('scans', 'progress')
    op.drop_column('scans', 'stage')