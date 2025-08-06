from flask_mail import Message
from app import mail, app
import logging
import secrets

logger = logging.getLogger(__name__)

class EmailManager:
    @staticmethod
    def send_verification_email(email, token):
        """Send email verification OTP"""
        try:
            # Generate 6-digit OTP from token
            otp = str(abs(hash(token)) % 1000000).zfill(6)
            
            msg = Message(
                subject='Secure Messaging - Email Verification',
                recipients=[email],
                html=f"""
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #333;">Email Verification Required</h2>
                    <p>Your verification code is:</p>
                    <div style="background-color: #f8f9fa; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
                        <h1 style="color: #007bff; font-size: 32px; margin: 0; letter-spacing: 5px;">{otp}</h1>
                    </div>
                    <p>This code will expire in 24 hours.</p>
                    <p>If you didn't request this verification, please ignore this email.</p>
                    <hr style="margin: 30px 0;">
                    <p style="color: #666; font-size: 12px;">
                        This is an automated message from Secure Messaging System.
                    </p>
                </div>
                """,
                body=f"""
                Email Verification Required
                
                Your verification code is: {otp}
                
                This code will expire in 24 hours.
                If you didn't request this verification, please ignore this email.
                
                ---
                This is an automated message from Secure Messaging System.
                """
            )
            
            with app.app_context():
                mail.send(msg)
            
            logger.info(f"Verification email sent to {email}")
            return True
            
        except Exception as e:
            logger.error(f"Error sending verification email to {email}: {e}")
            return False
    
    @staticmethod
    def generate_otp_from_token(token):
        """Generate consistent 6-digit OTP from token"""
        return str(abs(hash(token)) % 1000000).zfill(6)
