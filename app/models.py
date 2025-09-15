from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from . import db
from itsdangerous import URLSafeTimedSerializer as Serializer, BadSignature, SignatureExpired
from flask import current_app
from . import db, login_manager

from sqlalchemy.orm import relationship

channel_user = db.Table('channel_user',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('channel_id', db.Integer, db.ForeignKey('channel.id'), primary_key=True)
)

class Channel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    description = db.Column(db.String(256))
    users = relationship('User', secondary=channel_user, back_populates='channels')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(128), nullable=False)
    company_size = db.Column(db.String(128), nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    channels = db.relationship('Channel', secondary=channel_user, back_populates='users')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_verification_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_verification_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token, max_age=3600)  # max_age specifies the expiration time
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        return User.query.get(data['user_id'])
    
    @property
    def is_active(self):
        return self.email_verified

    def get_id(self):
        return str(self.id)