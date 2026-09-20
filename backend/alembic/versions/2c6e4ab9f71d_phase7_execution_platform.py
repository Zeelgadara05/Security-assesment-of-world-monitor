"""Phase 7 execution platform

Adds the real-execution architecture:

  * new tables: ``tool_readiness`` (preflight probes), ``tool_executions``
    (bounded process telemetry + retry attempt), ``scan_stages`` (pipeline
    stage ledger), ``scan_events`` (append-only typed event stream),
    ``finding_validations`` (deterministic validator verdicts),
    ``finding_observation_links`` (provenance edges) and ``ml_inferences``
    (explicit advisory-only marker -- no model is ever silently loaded).
  * ``scans`` gains the Phase 7 state machine fields (``state``,
    ``preflight_json``, queue timing) -- a superset of the legacy ``stage``.
  * ``vulnerabilities`` gains cross-scan tracking columns (``first_scan_id``,
    ``last_scan_id``, ``occurrence_count``).

Every added column is nullable (or defaults) so existing Phase 3-6 rows remain
valid and every table is additive -- nothing is dropped or rewritten.

Revision ID: 2c6e4ab9f71d
Revises: a9f3e2d1c8b4
Create Date: 2026-09-20 14:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2c6e4ab9f71d'
down_revision: Union[str, Sequence[str], None] = 'a9f3e2d1c8b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # --- Scan: Phase 7 state machine -----------------------------------------
    op.add_column('scans', sa.Column('state', sa.String(length=50), nullable=True))
    op.create_index('ix_scans_state', 'scans', ['state'])
    op.add_column('scans', sa.Column('preflight_json', sa.JSON(), nullable=True))
    op.add_column('scans', sa.Column('queue_started_at', sa.DateTime(), nullable=True))
    op.add_column('scans', sa.Column('queue_waited_ms', sa.Integer(), nullable=True))

    # --- Vulnerability: cross-scan tracking ----------------------------------
    op.add_column('vulnerabilities', sa.Column('first_scan_id', sa.Integer(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('last_scan_id', sa.Integer(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('occurrence_count', sa.Integer(), nullable=True))

    # --- tool_readiness ------------------------------------------------------
    op.create_table(
        'tool_readiness',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('tool', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('executable', sa.String(length=500), nullable=True),
        sa.Column('version', sa.String(length=200), nullable=True),
        sa.Column('adapter', sa.String(length=50), nullable=True),
        sa.Column('category', sa.String(length=50), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('reason', sa.String(length=255), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('checked_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tool_readiness_scan_id', 'tool_readiness', ['scan_id'])

    # --- tool_executions -----------------------------------------------------
    op.create_table(
        'tool_executions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('stage', sa.String(length=50), nullable=False),
        sa.Column('tool', sa.String(length=50), nullable=False),
        sa.Column('adapter', sa.String(length=50), nullable=True),
        sa.Column('attempt', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('executable', sa.String(length=500), nullable=True),
        sa.Column('tool_version', sa.String(length=200), nullable=True),
        sa.Column('target', sa.String(length=255), nullable=True),
        sa.Column('command_redacted', sa.Text(), nullable=True),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('stdout_size', sa.Integer(), nullable=True),
        sa.Column('stderr_size', sa.Integer(), nullable=True),
        sa.Column('stdout_truncated', sa.Boolean(), nullable=True),
        sa.Column('stderr_truncated', sa.Boolean(), nullable=True),
        sa.Column('parsed_observations', sa.Integer(), nullable=True),
        sa.Column('cancellation_state', sa.String(length=50), nullable=True),
        sa.Column('termination_reason', sa.String(length=255), nullable=True),
        sa.Column('error_code', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_tool_executions_scan_id', 'tool_executions', ['scan_id'])

    # --- scan_stages ---------------------------------------------------------
    op.create_table(
        'scan_stages',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('order', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('tools', sa.JSON(), nullable=True),
        sa.Column('tests_executed', sa.Integer(), nullable=True),
        sa.Column('observations', sa.Integer(), nullable=True),
        sa.Column('candidates', sa.Integer(), nullable=True),
        sa.Column('confirmed_findings', sa.Integer(), nullable=True),
        sa.Column('errors', sa.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('finished_at', sa.DateTime(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scan_stages_scan_id', 'scan_stages', ['scan_id'])

    # --- scan_events ---------------------------------------------------------
    op.create_table(
        'scan_events',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('event_type', sa.String(length=50), nullable=False),
        sa.Column('data', sa.JSON(), nullable=True),
        sa.Column('seq', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_scan_events_scan_id', 'scan_events', ['scan_id'])
    op.create_index('ix_scan_events_created_at', 'scan_events', ['created_at'])

    # --- finding_validations -------------------------------------------------
    op.create_table(
        'finding_validations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('finding_id', sa.Integer(), nullable=True),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('validator_id', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('condition', sa.Text(), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('expected', sa.Text(), nullable=True),
        sa.Column('actual', sa.Text(), nullable=True),
        sa.Column('security_boundary', sa.Text(), nullable=True),
        sa.Column('confidence', sa.String(length=20), nullable=True),
        sa.Column('observation_id', sa.Integer(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('duration_ms', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['finding_id'], ['vulnerabilities.id'], ),
        sa.ForeignKeyConstraint(['observation_id'], ['observations.id'], ),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_finding_validations_finding_id', 'finding_validations', ['finding_id'])
    op.create_index('ix_finding_validations_scan_id', 'finding_validations', ['scan_id'])

    # --- finding_observation_links ------------------------------------------
    op.create_table(
        'finding_observation_links',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('finding_id', sa.Integer(), nullable=False),
        sa.Column('observation_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['finding_id'], ['vulnerabilities.id'], ),
        sa.ForeignKeyConstraint(['observation_id'], ['observations.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_finding_observation_links_finding_id', 'finding_observation_links', ['finding_id'])
    op.create_index('ix_finding_observation_links_observation_id', 'finding_observation_links', ['observation_id'])

    # --- ml_inferences -------------------------------------------------------
    op.create_table(
        'ml_inferences',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('model_name', sa.String(length=100), nullable=True),
        sa.Column('model_version', sa.String(length=100), nullable=True),
        sa.Column('model_type', sa.String(length=50), nullable=True),
        sa.Column('feature_schema_version', sa.String(length=50), nullable=True),
        sa.Column('training_status', sa.String(length=50), nullable=True),
        sa.Column('input_source', sa.String(length=50), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('advisory_json', sa.JSON(), nullable=True),
        sa.Column('generated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_ml_inferences_scan_id', 'ml_inferences', ['scan_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_ml_inferences_scan_id', table_name='ml_inferences')
    op.drop_table('ml_inferences')

    op.drop_index('ix_finding_observation_links_observation_id', table_name='finding_observation_links')
    op.drop_index('ix_finding_observation_links_finding_id', table_name='finding_observation_links')
    op.drop_table('finding_observation_links')

    op.drop_index('ix_finding_validations_scan_id', table_name='finding_validations')
    op.drop_index('ix_finding_validations_finding_id', table_name='finding_validations')
    op.drop_table('finding_validations')

    op.drop_index('ix_scan_events_created_at', table_name='scan_events')
    op.drop_index('ix_scan_events_scan_id', table_name='scan_events')
    op.drop_table('scan_events')

    op.drop_index('ix_scan_stages_scan_id', table_name='scan_stages')
    op.drop_table('scan_stages')

    op.drop_index('ix_tool_executions_scan_id', table_name='tool_executions')
    op.drop_table('tool_executions')

    op.drop_index('ix_tool_readiness_scan_id', table_name='tool_readiness')
    op.drop_table('tool_readiness')

    op.drop_column('vulnerabilities', 'occurrence_count')
    op.drop_column('vulnerabilities', 'last_scan_id')
    op.drop_column('vulnerabilities', 'first_scan_id')

    op.drop_column('scans', 'queue_waited_ms')
    op.drop_column('scans', 'queue_started_at')
    op.drop_column('scans', 'preflight_json')
    op.drop_index('ix_scans_state', table_name='scans')
    op.drop_column('scans', 'state')