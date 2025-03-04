"""Add vulnerability model

Revision ID: e4b29ac7f4e2
Revises: previous_revision_id
Create Date: 2025-03-02 07:10:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import Column, Integer, String, DateTime, Enum, JSON, ForeignKey, Boolean
import enum

# revision identifiers, used by Alembic.
revision = 'e4b29ac7f4e2'
down_revision = 'previous_revision_id'  # Replace with your actual previous revision
branch_labels = None
depends_on = None

class VulnerabilityType(enum.Enum):
    XSS = "xss"
    # Future types can be added here

def upgrade():
    # Create enum type for vulnerability types
    vulnerability_type = sa.Enum(VulnerabilityType, name='vulnerabilitytype')
    vulnerability_type.create(op.get_bind(), checkfirst=True)
    
    # Create vulnerabilities table
    op.create_table(
        'vulnerabilities',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('endpoint_id', sa.Integer, sa.ForeignKey('endpoints.id')),
        sa.Column('type', vulnerability_type),
        sa.Column('parameter', sa.String),
        sa.Column('payload', sa.String),
        sa.Column('proof', sa.String),
        sa.Column('severity', sa.String),
        sa.Column('discovery_time', sa.DateTime, default=sa.func.current_timestamp()),
        sa.Column('additional_info', sa.JSON),
    )
    
    # Create index on endpoint_id
    op.create_index('ix_vulnerabilities_endpoint_id', 'vulnerabilities', ['endpoint_id'])

def downgrade():
    # Drop the vulnerabilities table
    op.drop_table('vulnerabilities')
    
    # Drop the enum type
    vulnerability_type = sa.Enum(VulnerabilityType, name='vulnerabilitytype')
    vulnerability_type.drop(op.get_bind(), checkfirst=True)