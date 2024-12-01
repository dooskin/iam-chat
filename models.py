from database import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(64), nullable=False, default='user')
    
    def __init__(self, username, email, password_hash, role='user'):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    type = db.Column(db.String(64), nullable=False)
    
    __table_args__ = (
        db.UniqueConstraint('name', name='uq_resource_name'),
    )

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(64), nullable=False)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=False)
    action = db.Column(db.String(64), nullable=False)  # read, write, execute, etc.
    
    __table_args__ = (
        db.UniqueConstraint('role', 'resource_id', 'action', name='uq_permission_role_resource_action'),
    )

class CompliancePolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(64), nullable=False)  # e.g., 'GDPR', 'SOX', 'HIPAA'
    requirements = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(32), default='active')  # active, archived, draft
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

    __table_args__ = (
        db.UniqueConstraint('name', 'category', name='uq_compliance_policy_name_category'),
    )

class ComplianceRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('compliance_policy.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=False)
    status = db.Column(db.String(32), nullable=False)  # compliant, non_compliant, pending_review
    evidence = db.Column(db.Text)
    reviewed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=db.func.now())
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now())

    policy = db.relationship('CompliancePolicy', backref='records')
    user = db.relationship('User', foreign_keys=[user_id], backref='compliance_records')
    resource = db.relationship('Resource', backref='compliance_records')
    reviewer = db.relationship('User', foreign_keys=[reviewed_by], backref='reviewed_records')