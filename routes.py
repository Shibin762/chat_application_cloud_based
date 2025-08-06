from flask import render_template, redirect, url_for, flash, request, session, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from app import app, db
from models import User, Message, EmailVerification
from forms import RegistrationForm, LoginForm, ComposeMessageForm, EmailVerificationForm
from crypto_utils import CryptoManager
from email_utils import EmailManager
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # type: ignore
login_manager.login_message_category = 'info'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('messages'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            # Generate RSA key pair
            private_key, public_key = CryptoManager.generate_rsa_keypair()
            
            # Create user
            user = User(
                username=form.username.data,
                email=form.email.data,
                public_key=public_key,
                private_key=private_key
            )
            user.set_password(form.password.data)
            
            db.session.add(user)
            db.session.flush()  # Get user.id before creating verification
            
            # Create email verification
            verification = EmailVerification(
                user_id=user.id,
                email=user.email
            )
            db.session.add(verification)
            db.session.commit()
            
            # Send verification email
            if EmailManager.send_verification_email(user.email, verification.token):
                flash('Registration successful! Please check your email to verify your account.', 'success')
                return redirect(url_for('verify_email', token=verification.token))
            else:
                # If email fails, auto-verify for now (development mode)
                user.is_verified = True
                db.session.commit()
                flash('Registration successful! You can now log in (email verification bypassed for testing).', 'success')
                return redirect(url_for('login'))
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error: {e}")
            flash('An error occurred during registration. Please try again.', 'danger')
    
    return render_template('register.html', form=form)

@app.route('/verify_email/<token>', methods=['GET', 'POST'])
def verify_email(token):
    verification = EmailVerification.query.filter_by(token=token, is_used=False).first()
    if not verification or verification.is_expired():
        flash('Invalid or expired verification link.', 'danger')
        return redirect(url_for('login'))
    
    form = EmailVerificationForm()
    form.token.data = token
    
    if form.validate_on_submit():
        entered_otp = form.otp.data
        expected_otp = EmailManager.generate_otp_from_token(token)
        
        if entered_otp == expected_otp:
            # Verify user
            user = User.query.get(verification.user_id)
            if user:
                user.is_verified = True
            verification.is_used = True
            
            db.session.commit()
            
            flash('Email verified successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')
    
    return render_template('verify_email.html', form=form, email=verification.email)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            if not user.is_verified:
                flash('Please verify your email address before logging in.', 'warning')
                return redirect(url_for('login'))
            
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('messages'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent messages
    recent_messages = Message.query.filter(
        (Message.sender_id == current_user.id) | (Message.recipient_id == current_user.id)
    ).order_by(Message.timestamp.desc()).limit(10).all()
    
    # Get unread count
    unread_count = Message.query.filter_by(recipient_id=current_user.id, is_read=False).count()
    
    # Get verified users count
    verified_users = User.query.filter_by(is_verified=True).count() - 1  # Exclude current user
    
    return render_template('dashboard.html', 
                         recent_messages=recent_messages,
                         unread_count=unread_count,
                         verified_users=verified_users)

@app.route('/messages')
@login_required
def messages():
    # Get all messages for current user
    inbox = Message.query.filter_by(recipient_id=current_user.id).order_by(Message.timestamp.desc()).all()
    sent = Message.query.filter_by(sender_id=current_user.id).order_by(Message.timestamp.desc()).all()
    
    # Decrypt messages
    decrypted_inbox = []
    for msg in inbox:
        try:
            decrypted_content = CryptoManager.decrypt_message(
                msg.encrypted_content,
                msg.encrypted_key,
                current_user.private_key
            )
            decrypted_inbox.append({
                'id': msg.id,
                'sender': msg.sender,
                'content': decrypted_content,
                'timestamp': msg.timestamp,
                'is_read': msg.is_read,
                'encrypted_content': msg.encrypted_content,
                'encrypted_key': msg.encrypted_key
            })
        except Exception as e:
            logger.error(f"Error decrypting message {msg.id}: {e}")
            decrypted_inbox.append({
                'id': msg.id,
                'sender': msg.sender,
                'content': '[Error: Could not decrypt message]',
                'timestamp': msg.timestamp,
                'is_read': msg.is_read,
                'encrypted_content': msg.encrypted_content,
                'encrypted_key': msg.encrypted_key
            })
    
    return render_template('messages.html', inbox=decrypted_inbox, sent=sent)

@app.route('/compose', methods=['GET', 'POST'])
@login_required
def compose():
    form = ComposeMessageForm(current_user)
    
    if form.validate_on_submit():
        try:
            recipient = User.query.get(form.recipient.data)
            if not recipient or not recipient.is_verified:
                flash('Invalid recipient selected.', 'danger')
                return redirect(url_for('compose'))
            
            # Encrypt message
            encrypted_data = CryptoManager.encrypt_message(form.message.data, recipient.public_key)
            
            # Create message
            message = Message(
                sender_id=current_user.id,
                recipient_id=recipient.id,
                encrypted_content=encrypted_data['encrypted_content'],
                encrypted_key=encrypted_data['encrypted_key']
            )
            
            db.session.add(message)
            db.session.commit()
            
            flash(f'Message sent to {recipient.username} successfully!', 'success')
            return redirect(url_for('messages'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error sending message: {e}")
            flash('Error sending message. Please try again.', 'danger')
    
    return render_template('compose.html', form=form)

@app.route('/mark_read/<int:message_id>')
@login_required
def mark_read(message_id):
    message = Message.query.get_or_404(message_id)
    if message.recipient_id == current_user.id:
        message.is_read = True
        db.session.commit()
    return redirect(url_for('messages'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500
