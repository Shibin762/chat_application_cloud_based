from app import db
from flask_login import UserMixin
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)  # This would be encrypted in production
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, username=None, email=None, public_key=None, private_key=None):
        self.username = username
        self.email = email
        self.public_key = public_key
        self.private_key = private_key
    
    # Relationships
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender')
    received_messages = db.relationship('Message', foreign_keys='Message.recipient_id', backref='recipient')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)
    encrypted_key = db.Column(db.Text, nullable=False)  # RSA encrypted Fernet key
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    
    def __init__(self, sender_id=None, recipient_id=None, encrypted_content=None, encrypted_key=None):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.encrypted_content = encrypted_content
        self.encrypted_key = encrypted_key
    
    def __repr__(self):
        return f'<Message from {self.sender_id} to {self.recipient_id}>'

class EmailVerification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    token = db.Column(db.String(32), nullable=False, default=lambda: secrets.token_hex(16))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, default=lambda: datetime.utcnow() + timedelta(hours=24))
    is_used = db.Column(db.Boolean, default=False)
    
    def __init__(self, user_id=None, email=None):
        self.user_id = user_id
        self.email = email
    
    user = db.relationship('User', backref='verification_tokens')
    
    def is_expired(self):
        return datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f'<EmailVerification for {self.email}>'
