"""Add payment_intent to Transaction

Revision ID: 24790c500051
Revises: 
Create Date: 2025-07-02 02:01:17.729646

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '24790c500051'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transaction', schema=None) as batch_op:
        batch_op.add_column(sa.Column('payment_intent', sa.String(length=255), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('transaction', schema=None) as batch_op:
        batch_op.drop_column('payment_intent')

    # ### end Alembic commands ###
