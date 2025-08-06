# chat_application_cloud_based

# Secure Messaging System

A Flask-based end-to-end encrypted messaging platform with hybrid encryption (RSA + Fernet), email verification, and a modern dark-themed interface.

## Features

### 🔐 Security
- **End-to-End Encryption**: Messages encrypted with hybrid RSA + Fernet encryption
- **Automatic Key Generation**: RSA key pairs generated for each user
- **Secure Authentication**: Password hashing with Werkzeug security
- **CSRF Protection**: Flask-WTF token validation
- **Security Headers**: XSS protection, content type options, frame options

### 👤 User Management
- **Registration System**: Create accounts with email verification
- **Email Verification**: OTP-based email verification (with development bypass)
- **Session Management**: Flask-Login for secure user sessions
- **Password Validation**: Secure password requirements and confirmation

### 💬 Messaging
- **Encrypted Messages**: Send and receive encrypted messages between users
- **Message History**: View all sent and received messages
- **Read Status Tracking**: Track message read status
- **Raw Data View**: Inspect encrypted message data for educational purposes

### 🎨 User Interface
- **Dark Theme**: Modern Bootstrap-based dark interface
- **Responsive Design**: Works on desktop and mobile devices
- **Dashboard**: Overview of messages, users, and account status
- **Form Validation**: Real-time client and server-side validation

## Technology Stack

### Backend
- **Flask**: Core web framework
- **SQLAlchemy**: Database ORM
- **PostgreSQL**: Production database (SQLite for development)
- **Flask-Login**: User session management
- **Flask-Mail**: Email delivery system
- **Flask-WTF**: Form handling and CSRF protection

### Security & Cryptography
- **PyCryptodome**: RSA key generation and encryption
- **cryptography**: Fernet symmetric encryption
- **Werkzeug**: Password hashing utilities

### Frontend
- **Bootstrap 5**: Responsive CSS framework
- **Replit Dark Theme**: Custom Bootstrap theme
- **Font Awesome**: Icon library
- **Jinja2**: Template engine

## Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL database (or SQLite for development)
- Gmail account for SMTP (optional, auto-verification enabled for testing)

### Installation

1. **Clone and Setup**
```bash
# Dependencies are already installed in this Replit environment
```

2. **Environment Variables**
```bash
# Required
DATABASE_URL=postgresql://...
SESSION_SECRET=your-secret-key

# Optional (for email verification)
MAIL_USERNAME=your-gmail@gmail.com
MAIL_PASSWORD=your-app-password
```

3. **Run the Application**
```bash
# Start the server
gunicorn --bind 0.0.0.0:5000 --reuse-port --reload main:app
```

4. **Access the Application**
- Open your browser to `http://localhost:5000`
- Register a new account or use test credentials

## Test Accounts

For demonstration purposes, these accounts are available:

```
Username: demo
Password: demo123

Username: alice  
Password: alice123
```

## Usage Guide

### 1. Registration
- Visit the homepage and click "Register"
- Fill in username, email, and password
- Account is automatically verified in development mode
- Redirected to login page upon successful registration

### 2. Login
- Enter your username and password
- Automatically redirected to messages dashboard after successful login

### 3. Sending Messages
- Click "New Message" from the dashboard
- Select recipient from dropdown
- Type your message and click "Send"
- Message is automatically encrypted with recipient's public key

### 4. Viewing Messages
- All received messages appear in your inbox
- Click "View Encrypted Data" to see raw encrypted content
- Messages are automatically decrypted when displayed

## How Encryption Works

### Hybrid Encryption Process

1. **Key Generation**: Each user gets a unique RSA key pair (2048-bit)
2. **Message Encryption**: 
   - Generate random Fernet key for message content
   - Encrypt message with Fernet (fast symmetric encryption)
   - Encrypt Fernet key with recipient's RSA public key
3. **Storage**: Both encrypted message and encrypted key stored in database
4. **Decryption**:
   - Decrypt Fernet key using recipient's RSA private key
   - Use decrypted Fernet key to decrypt message content

This approach combines RSA's security with Fernet's performance for optimal encryption.

## Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `email`: Unique email address
- `password_hash`: Hashed password
- `public_key`: RSA public key (PEM format)
- `private_key`: RSA private key (PEM format)
- `is_verified`: Email verification status

### Messages Table
- `id`: Primary key
- `sender_id`: Foreign key to Users
- `recipient_id`: Foreign key to Users
- `encrypted_content`: Base64 encrypted message
- `encrypted_key`: RSA encrypted Fernet key
- `timestamp`: Message creation time
- `is_read`: Read status

### Email Verification Table
- `id`: Primary key
- `user_id`: Foreign key to Users
- `email`: Email address
- `token`: Verification token
- `created_at`: Token creation time
- `expires_at`: Token expiration time
- `is_used`: Whether token has been used

## Configuration

### Email Settings
Configure SMTP settings in environment variables:
```
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USE_TLS=True
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### Database Settings
```
DATABASE_URL=postgresql://username:password@host:port/database
```

### Security Settings
```
SESSION_SECRET=your-secret-session-key
```

## Development

### File Structure
```
├── app.py              # Flask app initialization
├── main.py             # Application entry point
├── routes.py           # URL routes and view functions
├── models.py           # Database models
├── forms.py            # WTForms form definitions
├── crypto_utils.py     # Encryption utilities
├── email_utils.py      # Email sending utilities
├── templates/          # HTML templates
├── static/             # CSS, JS, and other static files
└── README.md           # This file
```

### Adding New Features

1. **New Routes**: Add to `routes.py`
2. **Database Changes**: Modify `models.py` and run migrations
3. **Forms**: Define in `forms.py`
4. **Templates**: Add to `templates/` directory
5. **Styling**: Use Bootstrap classes, custom CSS in `static/css/`

## Security Considerations

- RSA keys are generated per user and stored securely
- Messages cannot be decrypted without the recipient's private key
- Passwords are hashed using Werkzeug's secure methods
- CSRF tokens protect against cross-site request forgery
- Session management handled by Flask-Login
- SQL injection prevention through SQLAlchemy ORM

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is for educational purposes. Use responsibly and in accordance with applicable laws and regulations.

## Support

For questions or issues, please refer to the code documentation or create an issue in the repository.

---

**Note**: This system is designed for educational purposes to demonstrate end-to-end encryption concepts. For production use, additional security measures and auditing should be implemented.
