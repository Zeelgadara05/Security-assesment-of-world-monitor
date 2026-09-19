"""observations and finding pipeline

Adds the evidence foundation of Phase 3: a persisted ``observations`` table is
the single accepted source of factual data, and the ``vulnerabilities`` table
grows the finding-pipeline columns (rule_id, triage state, dedup key, evidence
trail) so every finding is traceable to persisted observations.

Revision ID: 8f3a2c51d94e6b77
Revises: e8244e2719f7
Create Date: 2026-09-19 16:40:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8f3a2c51d94e6b77'
down_revision: Union[str, Sequence[str], None] = 'e8244e2719f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('observations',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('scan_id', sa.Integer(), nullable=False),
    sa.Column('tool_name', sa.String(length=50), nullable=False),
    sa.Column('kind', sa.String(length=50), nullable=False),
    sa.Column('subject', sa.String(length=255), nullable=False),
    sa.Column('data_json', sa.JSON(), nullable=True),
    sa.Column('raw_output', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.add_column('vulnerabilities', sa.Column('cwe', sa.String(length=100), nullable=True))
    op.add_column('vulnerabilities', sa.Column('rule_id', sa.String(length=100), nullable=True))
    op.add_column('vulnerabilities', sa.Column('dedup_key', sa.String(length=255), nullable=True))
    op.add_column('vulnerabilities', sa.Column('confidence', sa.String(length=20), nullable=True))
    op.add_column('vulnerabilities', sa.Column('state', sa.String(length=50), nullable=False, server_default='NEW'))
    op.add_column('vulnerabilities', sa.Column('evidence', sa.Text(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('evidence_observation_ids', sa.JSON(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('updated_at', sa.DateTime(), nullable=True))
    op.add_column('vulnerabilities', sa.Column('resolved_at', sa.DateTime(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('vulnerabilities', 'resolved_at')
    op.drop_column('vulnerabilities', 'updated_at')
    op.drop_column('vulnerabilities', 'evidence_observation_ids')
    op.drop_column('vulnerabilities', 'evidence')
    op.drop_column('vulnerabilities', 'state')
    op.drop_column('vulnerabilities', 'confidence')
    op.drop_column('vulnerabilities', 'dedup_key')
    op.drop_column('vulnerabilities', 'rule_id')
    op.drop_column('vulnerabilities', 'cwe')
    op.drop_table('observations')