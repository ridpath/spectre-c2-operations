"""rename metadata to evidence_metadata

Revision ID: 003_rename_metadata
Revises: 002_add_indexes
Create Date: 2026-01-10 18:06:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '003_rename_metadata'
down_revision = '002_add_indexes'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column('evidence', 'metadata', new_column_name='evidence_metadata')
    op.alter_column('iq_recordings', 'metadata', new_column_name='iq_metadata')


def downgrade():
    op.alter_column('evidence', 'evidence_metadata', new_column_name='metadata')
    op.alter_column('iq_recordings', 'iq_metadata', new_column_name='metadata')
