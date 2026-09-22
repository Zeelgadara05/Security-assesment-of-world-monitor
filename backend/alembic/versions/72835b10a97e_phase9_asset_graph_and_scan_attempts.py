"""Phase 9 asset graph + scan attempts (additive)

Adds the Phase 9 data-model surfaces without dropping, renaming or rewriting
anything:

  * ``assets``            -- parent_asset_id (self-FK for the asset graph),
                             source (who discovered it), scan_id (which scan
                             first surfaced it).  All nullable.
  * ``observations``      -- asset_id (which graph asset the fact concerns).
  * ``vulnerabilities``   -- endpoint_asset_id (which asset the finding
                             concerns) + cve_status (observed / potentially_
                             affected / confirmed).
  * ``scans``             -- schedule_cadence (operator hint) + attempt_count
                             (derived counter, additive).
  * ``scan_attempts``     -- NEW audit trail: every enqueued execution of a
                             scan (initial, retry, schedule) gets one row with
                             trigger/status/result so retries are traceable.

Foreign keys are added with explicit names so the migration is dialect-safe
(SQLite + PostgreSQL); every new column/index is nullable / additive.

Revision ID: 72835b10a97e
Revises: 9a4b7c2e5f10
Create Date: 2026-09-21 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '72835b10a97e'
down_revision: Union[str, Sequence[str], None] = '9a4b7c2e5f10'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema (additive only)."""
    # --- assets: asset-graph edges --------------------------------
    with op.batch_alter_table('assets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('parent_asset_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('source', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('scan_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_assets_parent_asset_id', 'assets',
                                    ['parent_asset_id'], ['id'])
        batch_op.create_foreign_key('fk_assets_scan_id', 'scans', ['scan_id'], ['id'])
        batch_op.create_index('ix_assets_scan_id', ['scan_id'], unique=False)

    # --- observations: asset link ----------------------------------
    with op.batch_alter_table('observations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('asset_id', sa.Integer(), nullable=True))
        batch_op.create_index('ix_observations_asset_id', ['asset_id'], unique=False)
        batch_op.create_foreign_key('fk_observations_asset_id', 'assets',
                                    ['asset_id'], ['id'])

    # --- vulnerabilities: asset provenance + CVE correlation state --
    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.add_column(sa.Column('endpoint_asset_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('cve_status', sa.String(length=20), nullable=True))
        batch_op.create_index('ix_vulnerabilities_endpoint_asset_id',
                              ['endpoint_asset_id'], unique=False)
        batch_op.create_foreign_key('fk_vulnerabilities_endpoint_asset_id', 'assets',
                                    ['endpoint_asset_id'], ['id'])

    # --- scans: schedule + attempt counter (derived, additive) -----
    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('schedule_cadence', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('attempt_count', sa.Integer(), nullable=True))

    # --- report_exports: HTML + PDF projections (additive) ----------
    with op.batch_alter_table('report_exports', schema=None) as batch_op:
        batch_op.add_column(sa.Column('content_html', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('content_pdf', sa.LargeBinary(), nullable=True))

    # --- scan_attempts: new audit table -----------------------------
    op.create_table(
        'scan_attempts',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('attempt_number', sa.Integer(), nullable=False),
        sa.Column('trigger', sa.String(length=50), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('result', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], name='fk_scan_attempts_scan_id'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scan_attempts_scan_id', 'scan_attempts', ['scan_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_scan_attempts_scan_id', table_name='scan_attempts')
    op.drop_table('scan_attempts')

    with op.batch_alter_table('scans', schema=None) as batch_op:
        batch_op.drop_column('attempt_count')
        batch_op.drop_column('schedule_cadence')

    with op.batch_alter_table('report_exports', schema=None) as batch_op:
        batch_op.drop_column('content_pdf')
        batch_op.drop_column('content_html')

    with op.batch_alter_table('vulnerabilities', schema=None) as batch_op:
        batch_op.drop_index('ix_vulnerabilities_endpoint_asset_id')
        batch_op.drop_column('cve_status')
        batch_op.drop_column('endpoint_asset_id')

    with op.batch_alter_table('observations', schema=None) as batch_op:
        batch_op.drop_index('ix_observations_asset_id')
        batch_op.drop_column('asset_id')

    with op.batch_alter_table('assets', schema=None) as batch_op:
        batch_op.drop_index('ix_assets_scan_id')
        batch_op.drop_column('scan_id')
        batch_op.drop_column('source')
        batch_op.drop_column('parent_asset_id')