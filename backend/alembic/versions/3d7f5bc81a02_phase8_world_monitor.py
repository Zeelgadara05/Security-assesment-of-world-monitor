"""Phase 8 World Monitor integration

Adds the World Monitor target layer on top of the Phase 7 execution platform:

  * new table: ``world_monitor_targets`` -- one explicitly configured,
    authorized World Monitor deployment per project (base_url + optional
    api_base_url/openapi_url, connectivity/discovery status, real probe JSON).
  * new table: ``world_monitor_api_endpoints`` -- normalized inventory of
    endpoints actually discovered from a deployment (method, path, operating
    id, source, optional observation link for the evidence chain).

Both tables are additive and every column is nullable or defaulted; nothing in
the existing schema is dropped, renamed or rewritten.  ``status`` is a
connectivity/discovery state (see the model module) and never ``secure`` or
``insecure`` -- security posture is derived only from assessment findings.

Revision ID: 3d7f5bc81a02
Revises: 2c6e4ab9f71d
Create Date: 2026-09-21 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3d7f5bc81a02'
down_revision: Union[str, Sequence[str], None] = '2c6e4ab9f71d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # --- world_monitor_targets ----------------------------------------------
    op.create_table(
        'world_monitor_targets',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('project_id', sa.Integer(), nullable=False),
        sa.Column('base_url', sa.String(length=255), nullable=False),
        sa.Column('api_base_url', sa.String(length=255), nullable=True),
        sa.Column('openapi_url', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('last_checked_at', sa.DateTime(), nullable=True),
        sa.Column('last_discovery_at', sa.DateTime(), nullable=True),
        sa.Column('discovered_version', sa.String(length=100), nullable=True),
        sa.Column('health_json', sa.JSON(), nullable=True),
        sa.Column('discovery_json', sa.JSON(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_world_monitor_targets_project_id', 'world_monitor_targets', ['project_id'])

    # --- world_monitor_api_endpoints ----------------------------------------
    op.create_table(
        'world_monitor_api_endpoints',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('method', sa.String(length=10), nullable=False),
        sa.Column('path', sa.String(length=512), nullable=False),
        sa.Column('operation_id', sa.String(length=255), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('authentication_hint', sa.String(length=255), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=True),
        sa.Column('last_seen', sa.DateTime(), nullable=True),
        sa.Column('observation_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['observation_id'], ['observations.id'], ),
        sa.ForeignKeyConstraint(['target_id'], ['world_monitor_targets.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_world_monitor_api_endpoints_target_id', 'world_monitor_api_endpoints', ['target_id'])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_world_monitor_api_endpoints_target_id', table_name='world_monitor_api_endpoints')
    op.drop_table('world_monitor_api_endpoints')

    op.drop_index('ix_world_monitor_targets_project_id', table_name='world_monitor_targets')
    op.drop_table('world_monitor_targets')