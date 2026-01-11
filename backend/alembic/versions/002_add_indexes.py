"""add performance indexes

Revision ID: 002_add_indexes
Revises: 001_initial
Create Date: 2024-01-10 17:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '002_add_indexes'
down_revision = '001_initial'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('ix_missions_status', 'missions', ['status'])
    op.create_index('ix_missions_created_at', 'missions', ['created_at'])
    op.create_index('ix_missions_target_norad_id', 'missions', ['target_norad_id'])
    
    op.create_index('ix_evidence_timestamp', 'evidence', ['timestamp'])
    op.create_index('ix_evidence_category', 'evidence', ['category'])
    
    op.create_index('ix_vulnerabilities_severity', 'vulnerabilities', ['severity'])
    op.create_index('ix_vulnerabilities_exploit_available', 'vulnerabilities', ['exploit_available'])
    
    op.create_index('ix_attack_steps_status', 'attack_steps', ['status'])
    op.create_index('ix_attack_steps_phase', 'attack_steps', ['phase'])
    
    op.create_index('ix_reports_generated_at', 'reports', ['generated_at'])
    op.create_index('ix_reports_format', 'reports', ['format'])
    
    op.create_index('ix_audit_logs_timestamp', 'audit_logs', ['timestamp'])
    op.create_index('ix_audit_logs_action', 'audit_logs', ['action'])
    op.create_index('ix_audit_logs_resource_type', 'audit_logs', ['resource_type'])
    
    op.create_index('ix_iq_recordings_recorded_at', 'iq_recordings', ['recorded_at'])
    op.create_index('ix_iq_recordings_satellite_name', 'iq_recordings', ['satellite_name'])


def downgrade():
    op.drop_index('ix_missions_status', table_name='missions')
    op.drop_index('ix_missions_created_at', table_name='missions')
    op.drop_index('ix_missions_target_norad_id', table_name='missions')
    
    op.drop_index('ix_evidence_timestamp', table_name='evidence')
    op.drop_index('ix_evidence_category', table_name='evidence')
    
    op.drop_index('ix_vulnerabilities_severity', table_name='vulnerabilities')
    op.drop_index('ix_vulnerabilities_exploit_available', table_name='vulnerabilities')
    
    op.drop_index('ix_attack_steps_status', table_name='attack_steps')
    op.drop_index('ix_attack_steps_phase', table_name='attack_steps')
    
    op.drop_index('ix_reports_generated_at', table_name='reports')
    op.drop_index('ix_reports_format', table_name='reports')
    
    op.drop_index('ix_audit_logs_timestamp', table_name='audit_logs')
    op.drop_index('ix_audit_logs_action', table_name='audit_logs')
    op.drop_index('ix_audit_logs_resource_type', table_name='audit_logs')
    
    op.drop_index('ix_iq_recordings_recorded_at', table_name='iq_recordings')
    op.drop_index('ix_iq_recordings_satellite_name', table_name='iq_recordings')
