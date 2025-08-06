from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SelectField, HiddenField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(), 
        Length(min=3, max=20, message="Username must be between 3 and 20 characters")
    ])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
        DataRequired(), 
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    password_confirm = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use a different email.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class ComposeMessageForm(FlaskForm):
    recipient = SelectField('Recipient', validators=[DataRequired()], coerce=int)
    message = TextAreaField('Message', validators=[
        DataRequired(),
        Length(max=5000, message="Message too long (max 5000 characters)")
    ])
    
    def __init__(self, current_user, *args, **kwargs):
        super(ComposeMessageForm, self).__init__(*args, **kwargs)
        # Populate recipient choices (exclude current user)
        users = User.query.filter(User.id != current_user.id, User.is_verified == True).all()
        self.recipient.choices = [(user.id, f"{user.username} ({user.email})") for user in users]

class EmailVerificationForm(FlaskForm):
    otp = StringField('Verification Code', validators=[
        DataRequired(),
        Length(min=6, max=6, message="Verification code must be 6 digits")
    ])
    token = HiddenField()
