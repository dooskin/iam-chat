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
