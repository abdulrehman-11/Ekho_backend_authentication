from flask import Blueprint, request, jsonify, current_app
from flask_login import login_user, login_required, logout_user, current_user
from flask_mail import Message
from .models import *
from . import db, mail  
import re

main = Blueprint('main', __name__)

@main.route('/', methods=['GET'])
def index():
    return jsonify({'message': 'Welcome to the API!'})

@main.route('/login', methods=['POST'])
def login():
    if current_user.is_authenticated:
        return jsonify({'message': 'You are already logged in!'})

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email or Password missing!'}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401

    if not user.email_verified:
        return jsonify({'error': 'Please verify your email address before logging in.'}), 401

    login_user(user)
    return jsonify({'message': 'Login successful!'})


@main.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')
    full_name = data.get('full_name')
    role = data.get('role')
    company_size = data.get('company_size')
    token = data.get('token')

    # Validation
    if not email or not password or not full_name or not role or not company_size:
        return jsonify({'error': 'All fields are required!'}), 400

    if not email.endswith('@thehexaa.com'):
        return jsonify({'error': 'Please enter a valid @thehexaa.com email address!'}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'User with this email already exists.'}), 400

    # Create new user
    user = User(
        email=email,
        full_name=full_name,
        role=role,
        company_size=company_size
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    if token:
        try:
            s = Serializer(current_app.config['SECRET_KEY'])
            data = s.loads(token)
            channel_id = data['channel_id']
            invited_email = data['email']
            if email == invited_email:
                channel = Channel.query.get(channel_id)
                if channel:
                    channel.users.append(user)
                    db.session.commit()
        except (BadSignature, SignatureExpired):
            return jsonify({'error': 'Invalid or expired invitation token.'}), 400

    send_verification_email(user)

    return jsonify({'message': 'Registration successful! A confirmation email has been sent.'})

@main.route('/confirm_email/<token>', methods=['GET'])
def confirm_email(token):
    user = User.verify_verification_token(token)
    if user is None:
        return jsonify({'error': 'The confirmation link is invalid or has expired.'}), 400

    user.email_verified = True
    db.session.commit()
    return jsonify({'message': 'Email verified successfully!'})


@main.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful!'})

def send_verification_email(user):
    token = user.generate_verification_token()
    verification_link = f"http://127.0.0.1:5000/confirm_email/{token}"  # Replace with your actual confirmation URL
    msg = Message('Confirm Your Email Address', sender=current_app.config['MAIL_USERNAME'], recipients=[user.email])
    msg.body = f'Please click the following link to verify your email address: {verification_link}'
    mail.send(msg)




@main.route('/create_channel', methods=['POST'])
@login_required
def create_channel():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')

    if not name:
        return jsonify({'error': 'Channel name is required!'}), 400

    channel = Channel(name=name, description=description)
    channel.users.append(current_user)  
    db.session.add(channel)
    db.session.commit()

    return jsonify({'message': 'Channel created successfully!', 'channel_id': channel.id}), 201


@main.route('/invite_to_channel', methods=['POST'])
@login_required
def invite_to_channel():
    data = request.get_json()
    channel_id = data.get('channel_id')
    invitee_email = data.get('invitee_email')

    if not channel_id or not invitee_email:
        return jsonify({'error': 'Channel ID and invitee email are required!'}), 400

    channel = Channel.query.get(channel_id)
    if not channel:
        return jsonify({'error': 'Channel not found!'}), 404

    invitee = User.query.filter_by(email=invitee_email).first()

    if invitee:
        if invitee in channel.users:
            return jsonify({'error': 'User is already a member of the channel!'}), 400
        channel.users.append(invitee)
        db.session.commit()
        send_invitation_email(invitee, channel)
        return jsonify({'message': 'User invited successfully!'}), 200
    else:
        send_invitation_email(None, channel, invitee_email)
        return jsonify({'message': 'Invitation sent successfully!'}), 200


def send_invitation_email(user, channel, invitee_email=None):
    current_app.logger.debug(f"Sending email to {user.email if user else invitee_email}")
    if user:
        msg = Message('You are invited to join a channel', sender=current_app.config['MAIL_USERNAME'], recipients=[user.email])
        msg.body = f'You have been invited to join the channel "{channel.name}".'
    else:
        token = generate_invitation_token(channel.id, invitee_email)
        registration_link = f"http://127.0.0.1:5000/register?token={token}"
        msg = Message('You are invited to join a channel', sender=current_app.config['MAIL_USERNAME'], recipients=[invitee_email])
        msg.body = f'You have been invited to join the channel "{channel.name}". Please register using the following link: {registration_link}'
    
    current_app.logger.debug(f"Email message: {msg.body}")
    mail.send(msg)
    current_app.logger.debug("Email sent successfully")


def generate_invitation_token(channel_id, email):
    s = Serializer(current_app.config['SECRET_KEY'])
    return s.dumps({'channel_id': channel_id, 'email': email})



