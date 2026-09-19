"""Phase 5 assessment engine

Adds the persistence foundation for real vulnerability assessment:

  * ``observations`` grows the normalized assessment fields (owner, normalized
    target/asset, observation_type, source, tool version, structured
    redacted request/response, fingerprint, status, observed_at).
  * ``vulnerabilities`` (the existing finding model) grows deterministic
    assessment metadata (category, endpoint, method, source test/tool,
    validation reason, impact).
  * ``tool_results`` grows per-execution telemetry (version, redacted command,
    timing, exit code, output sizes, parsed observation count).
  * two new tables: ``assessment_tests`` (planner/test ledger) and
    ``finding_evidence`` (structured, redacted evidence provenance).

Every added column is nullable so existing Phase 3/4 rows remain valid.

Revision ID: 8b1f4d2a6c30
Revises: 5c1d34a9e72f
Create Date: 2026-09-20 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8b1f4d2a6c30'
down_revision: Union[str, Sequence[str], None] = '5c1d34a9e72f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # --- Observation: normalized assessment fields -------------------------
    op.add_column('observations', sa.Column('user_id', sa.String(length=255), nullable=True))
    op.add_column('observations', sa.Column('target', sa.String(length=255), nullable=True))
    op.add_column('observations', sa.Column('asset', sa.String(length=255), nullable=True))
    op.add_column('observations', sa.Column('observation_type', sa.String(length=50), nullable=True))
    op.add_column('observations', sa.Column('source', sa.String(length=100), nullable=True))
    op.add_column('observations', sa.Column('tool_version', sa.String(length=100), nullable=True))
    op.add_column('observations', sa.Column('request_json', sa.JSON(), nullable=True))
    op.add_column('observations', sa.Column('response_json', sa.JSON(), nullable=True))
    op.add_column('observations', sa.Column('metadata_json', sa.JSON(), nullable=True))
    op.add_column('observations', sa.Column('fingerprint', sa.String(length=64), nullable=True))
    op.add_column('observations', sa.Column('status', sa.String(length=50), nullable=True))
    op.add_column('observations', sa.Column('observed_at', sa.DateTime(), nullable=True))

    # --- Vulnerability (finding): assessment metadata ----------------------
    op.add_column('vulnerabilities', sa.Column('category', sa.String(length=100), nullable=True))
    op.add_column('vulnerabilities', sa.Column('endpoint', sa.String(length=512), nullable=True))
    op.add_column('vulnerabilities', sa.Column('http_method', sa.String(length=20), nullable=True))
    op.add_column('vulnerabilities', sa.Column('source_test', sa.String(length=100), nullable=True))
    op.add_column('vulnerabilities', sa.Column('source_tool', sa.String(length=100), nullable=True))
    op.add_column('vulnerabilities', sa.Column('validation_reason', sa.Text(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('impact', sa.Text(), nullable=True))

    # --- ToolResult: execution telemetry -----------------------------------
    op.add_column('tool_results', sa.Column('tool_version', sa.String(length=100), nullable=True))
    op.add_column('tool_results', sa.Column('command_redacted', sa.Text(), nullable=True))
    op.add_column('tool_results', sa.Column('started_at', sa.DateTime(), nullable=True))
    op.add_column('tool_results', sa.Column('completed_at', sa.DateTime(), nullable=True))
    op.add_column('tool_results', sa.Column('exit_code', sa.Integer(), nullable=True))
    op.add_column('tool_results', sa.Column('duration_ms', sa.Integer(), nullable=True))
    op.add_column('tool_results', sa.Column('stdout_size', sa.Integer(), nullable=True))
    op.add_column('tool_results', sa.Column('stderr_size', sa.Integer(), nullable=True))
    op.add_column('tool_results', sa.Column('parsed_observations', sa.Integer(), nullable=True))

    # --- Assessment test ledger --------------------------------------------
    op.create_table(
        'assessment_tests',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('test_id', sa.String(length=100), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('category', sa.String(length=100), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='planned'),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('target', sa.String(length=255), nullable=True),
        sa.Column('endpoint', sa.String(length=512), nullable=True),
        sa.Column('http_method', sa.String(length=20), nullable=True),
        sa.Column('active', sa.Boolean(), nullable=True, server_default=sa.text('0')),
        sa.Column('required_observations', sa.JSON(), nullable=True),
        sa.Column('required_capabilities', sa.JSON(), nullable=True),
        sa.Column('observation_ids', sa.JSON(), nullable=True),
        sa.Column('finding_ids', sa.JSON(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )

    # --- Structured finding evidence ---------------------------------------
    op.create_table(
        'finding_evidence',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('finding_id', sa.Integer(), nullable=False),
        sa.Column('observation_id', sa.Integer(), nullable=True),
        sa.Column('evidence_type', sa.String(length=50), nullable=False),
        sa.Column('request_json', sa.JSON(), nullable=True),
        sa.Column('response_json', sa.JSON(), nullable=True),
        sa.Column('expected', sa.Text(), nullable=True),
        sa.Column('actual', sa.Text(), nullable=True),
        sa.Column('security_boundary', sa.Text(), nullable=True),
        sa.Column('redaction_status', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['finding_id'], ['vulnerabilities.id'], ),
        sa.ForeignKeyConstraint(['observation_id'], ['observations.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('finding_evidence')
    op.drop_table('assessment_tests')

    for column in (
        'parsed_observations', 'stderr_size', 'stdout_size', 'duration_ms',
        'exit_code', 'completed_at', 'started_at', 'command_redacted', 'tool_version',
    ):
        op.drop_column('tool_results', column)

    for column in (
        'impact', 'validation_reason', 'source_tool', 'source_test',
        'http_method', 'endpoint', 'category',
    ):
        op.drop_column('vulnerabilities', column)

    for column in (
        'observed_at', 'status', 'fingerprint', 'metadata_json', 'response_json',
        'request_json', 'tool_version', 'source', 'observation_type', 'asset',
        'target', 'user_id',
    ):
        op.drop_column('observations', column)
