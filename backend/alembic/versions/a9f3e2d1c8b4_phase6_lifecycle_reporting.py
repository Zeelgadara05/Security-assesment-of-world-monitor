"""Phase 6 finding lifecycle, evidence integrity & reporting

Extends the Phase 5 assessment foundation with:

  * ``vulnerabilities`` grows full lifecycle + reporting fields (status,
    affected_component, parameter, cvss_vector/score/version, business and
    technical impact, structured remediation, references, fingerprint,
    first_seen/last_seen).
  * ``finding_evidence`` gains integrity hashes over the redacted payload and
    bounded-capture metadata (original/captured size, truncation flag).
  * ``scans`` gains assessment status/completeness and a config snapshot.
  * two new tables: ``finding_status_history`` (immutable transition log) and
    ``report_exports`` (report reproducibility metadata).

Every added column is nullable (or defaults) so existing Phase 3-5 rows
remain valid.

Revision ID: a9f3e2d1c8b4
Revises: 8b1f4d2a6c30
Create Date: 2026-09-20 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a9f3e2d1c8b4'
down_revision: Union[str, Sequence[str], None] = '8b1f4d2a6c30'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # --- Vulnerability (finding): lifecycle + reporting --------------------
    op.add_column('vulnerabilities', sa.Column('status', sa.String(length=50),
                                               nullable=False, server_default='confirmed'))
    op.create_index('ix_vulnerabilities_status', 'vulnerabilities', ['status'])
    op.add_column('vulnerabilities', sa.Column('affected_component', sa.String(length=100), nullable=True))
    op.add_column('vulnerabilities', sa.Column('parameter', sa.String(length=255), nullable=True))
    op.add_column('vulnerabilities', sa.Column('cvss_version', sa.String(length=10), nullable=True))
    op.add_column('vulnerabilities', sa.Column('cvss_vector', sa.String(length=255), nullable=True))
    op.add_column('vulnerabilities', sa.Column('cvss_score', sa.Float(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('business_impact', sa.Text(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('technical_impact', sa.Text(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('impact_details', sa.JSON(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('remediation_details', sa.JSON(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('references_json', sa.JSON(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('fingerprint', sa.String(length=64), nullable=True))
    op.create_index('ix_vulnerabilities_fingerprint', 'vulnerabilities', ['fingerprint'])
    op.add_column('vulnerabilities', sa.Column('first_seen', sa.DateTime(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('last_seen', sa.DateTime(), nullable=True))

    # --- FindingEvidence: integrity + bounded capture ----------------------
    op.add_column('finding_evidence', sa.Column('request_hash', sa.String(length=64), nullable=True))
    op.add_column('finding_evidence', sa.Column('response_hash', sa.String(length=64), nullable=True))
    op.add_column('finding_evidence', sa.Column('original_size', sa.Integer(), nullable=True))
    op.add_column('finding_evidence', sa.Column('captured_size', sa.Integer(), nullable=True))
    op.add_column('finding_evidence', sa.Column('truncated', sa.Boolean(), nullable=True))
    op.create_index('ix_finding_evidence_finding_id', 'finding_evidence', ['finding_id'])

    # --- Scan: assessment status/completeness + config snapshot ------------
    op.add_column('scans', sa.Column('assessment_status', sa.String(length=50), nullable=True))
    op.add_column('scans', sa.Column('assessment_completeness', sa.String(length=50), nullable=True))
    op.add_column('scans', sa.Column('assessment_snapshot_json', sa.JSON(), nullable=True))

    # --- Immutable finding status history ----------------------------------
    op.create_table(
        'finding_status_history',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('finding_id', sa.Integer(), nullable=False),
        sa.Column('from_status', sa.String(length=50), nullable=False),
        sa.Column('to_status', sa.String(length=50), nullable=False),
        sa.Column('actor', sa.String(length=255), nullable=False, server_default='system'),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['finding_id'], ['vulnerabilities.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_finding_status_history_finding_id', 'finding_status_history', ['finding_id'])
    op.create_index('ix_finding_status_history_created_at', 'finding_status_history', ['created_at'])

    # --- Report export reproducibility metadata ----------------------------
    op.create_table(
        'report_exports',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('scan_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.String(length=255), nullable=True),
        sa.Column('format', sa.String(length=20), nullable=False),
        sa.Column('content_hash', sa.String(length=64), nullable=True),
        sa.Column('registry_fingerprint', sa.String(length=64), nullable=True),
        sa.Column('config_fingerprint', sa.String(length=64), nullable=True),
        sa.Column('content_length', sa.Integer(), nullable=True),
        sa.Column('generated_at', sa.DateTime(), nullable=True),
        sa.Column('content_json', sa.JSON(), nullable=True),
        sa.Column('content_markdown', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_report_exports_scan_id', 'report_exports', ['scan_id'])
    op.create_index('ix_report_exports_generated_at', 'report_exports', ['generated_at'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('report_exports')
    op.drop_table('finding_status_history')

    for column in ('assessment_snapshot_json', 'assessment_completeness', 'assessment_status'):
        op.drop_column('scans', column)

    op.drop_index('ix_finding_evidence_finding_id', table_name='finding_evidence')
    for column in ('truncated', 'captured_size', 'original_size', 'response_hash', 'request_hash'):
        op.drop_column('finding_evidence', column)

    op.drop_index('ix_vulnerabilities_fingerprint', table_name='vulnerabilities')
    op.drop_index('ix_vulnerabilities_status', table_name='vulnerabilities')
    for column in ('last_seen', 'first_seen', 'fingerprint', 'references_json',
                   'remediation_details', 'impact_details', 'technical_impact',
                   'business_impact', 'cvss_score', 'cvss_vector', 'cvss_version',
                   'parameter', 'affected_component', 'status'):
        op.drop_column('vulnerabilities', column)