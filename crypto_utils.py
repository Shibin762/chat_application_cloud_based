from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from cryptography.fernet import Fernet
import base64
import logging

logger = logging.getLogger(__name__)

class CryptoManager:
    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        """Generate RSA key pair"""
        try:
            key = RSA.generate(key_size)
            private_key = key.export_key().decode('utf-8')
            public_key = key.publickey().export_key().decode('utf-8')
            return private_key, public_key
        except Exception as e:
            logger.error(f"Error generating RSA key pair: {e}")
            raise
    
    @staticmethod
    def encrypt_message(message, recipient_public_key):
        """
        Encrypt message using hybrid encryption:
        1. Generate Fernet key for symmetric encryption
        2. Encrypt message with Fernet
        3. Encrypt Fernet key with recipient's RSA public key
        """
        try:
            # Generate Fernet key
            fernet_key = Fernet.generate_key()
            fernet = Fernet(fernet_key)
            
            # Encrypt message with Fernet
            encrypted_message = fernet.encrypt(message.encode('utf-8'))
            
            # Encrypt Fernet key with RSA
            rsa_key = RSA.import_key(recipient_public_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            encrypted_key = cipher.encrypt(fernet_key)
            
            return {
                'encrypted_content': base64.b64encode(encrypted_message).decode('utf-8'),
                'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8')
            }
        except Exception as e:
            logger.error(f"Error encrypting message: {e}")
            raise
    
    @staticmethod
    def decrypt_message(encrypted_content, encrypted_key, private_key):
        """
        Decrypt message using hybrid decryption:
        1. Decrypt Fernet key with RSA private key
        2. Decrypt message with Fernet key
        """
        try:
            # Decode base64
            encrypted_content_bytes = base64.b64decode(encrypted_content.encode('utf-8'))
            encrypted_key_bytes = base64.b64decode(encrypted_key.encode('utf-8'))
            
            # Decrypt Fernet key with RSA
            rsa_key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(rsa_key)
            fernet_key = cipher.decrypt(encrypted_key_bytes)
            
            # Decrypt message with Fernet
            fernet = Fernet(fernet_key)
            decrypted_message = fernet.decrypt(encrypted_content_bytes)
            
            return decrypted_message.decode('utf-8')
        except Exception as e:
            logger.error(f"Error decrypting message: {e}")
            raise
    
    @staticmethod
    def verify_key_pair(private_key, public_key):
        """Verify that private and public keys match"""
        try:
            # Test encryption/decryption
            test_message = "test_message"
            rsa_public = RSA.import_key(public_key)
            rsa_private = RSA.import_key(private_key)
            
            # Check if keys match by comparing public key derived from private key
            derived_public = rsa_private.publickey().export_key()
            return derived_public == rsa_public.export_key()
        except Exception as e:
            logger.error(f"Error verifying key pair: {e}")
            return False
