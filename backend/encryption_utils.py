import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import logging

logger = logging.getLogger(__name__)

class FieldEncryption:
    """
    Utility class for encrypting and decrypting sensitive database fields
    Uses Fernet (symmetric encryption) with key derivation from Django SECRET_KEY
    """
    
    _cipher = None
    
    @classmethod
    def _get_cipher(cls):
        """Get or create the Fernet cipher instance"""
        if cls._cipher is None:
            try:
                # Derive encryption key from Django SECRET_KEY
                secret_key = settings.SECRET_KEY.encode()
                salt = b'furniflex_salt_2024'  # Static salt for consistent key derivation
                
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(secret_key))
                cls._cipher = Fernet(key)
                
            except Exception as e:
                logger.error(f"Failed to initialize encryption cipher: {e}")
                raise ImproperlyConfigured("Encryption setup failed")
        
        return cls._cipher
    
    @classmethod
    def encrypt(cls, plaintext):
        """
        Encrypt a string value
        Returns base64 encoded encrypted string
        """
        if not plaintext:
            return plaintext
        
        try:
            cipher = cls._get_cipher()
            encrypted_bytes = cipher.encrypt(plaintext.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise
    
    @classmethod
    def decrypt(cls, encrypted_text):
        """
        Decrypt an encrypted string value
        Returns original plaintext string
        """
        if not encrypted_text:
            return encrypted_text
        
        try:
            cipher = cls._get_cipher()
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode('utf-8'))
            decrypted_bytes = cipher.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            # Return original value if decryption fails (for backward compatibility)
            return encrypted_text

class EncryptedCharField:
    """
    Custom field descriptor for automatic encryption/decryption of CharField data
    """
    
    def __init__(self, field_name):
        self.field_name = field_name
        self.encrypted_field_name = f"_{field_name}_encrypted"
    
    def __get__(self, instance, owner):
        if instance is None:
            return self
        
        encrypted_value = getattr(instance, self.encrypted_field_name, None)
        if encrypted_value:
            try:
                return FieldEncryption.decrypt(encrypted_value)
            except:
                return encrypted_value
        return encrypted_value
    
    def __set__(self, instance, value):
        if value:
            encrypted_value = FieldEncryption.encrypt(str(value))
            setattr(instance, self.encrypted_field_name, encrypted_value)
        else:
            setattr(instance, self.encrypted_field_name, value)

class DataEncryptionMixin:
    """
    Mixin class to add encryption capabilities to Django models
    """
    
    ENCRYPTED_FIELDS = []  # Override in subclasses
    
    def save(self, *args, **kwargs):
        """Override save to encrypt sensitive fields before saving"""
        self._encrypt_fields()
        super().save(*args, **kwargs)
    
    def _encrypt_fields(self):
        """Encrypt all fields listed in ENCRYPTED_FIELDS"""
        for field_name in self.ENCRYPTED_FIELDS:
            if hasattr(self, field_name):
                value = getattr(self, field_name)
                if value and not self._is_already_encrypted(field_name, value):
                    encrypted_value = FieldEncryption.encrypt(str(value))
                    setattr(self, f"_{field_name}_encrypted", encrypted_value)
                    # Clear the original field to prevent storing plaintext
                    setattr(self, field_name, None)
    
    def _is_already_encrypted(self, field_name, value):
        """Check if a value is already encrypted"""
        try:
            # Try to decrypt - if it works, it's encrypted
            FieldEncryption.decrypt(value)
            return True
        except:
            return False
    
    def get_decrypted_field(self, field_name):
        """Get decrypted value for a specific field"""
        if field_name in self.ENCRYPTED_FIELDS:
            encrypted_field = f"_{field_name}_encrypted"
            if hasattr(self, encrypted_field):
                encrypted_value = getattr(self, encrypted_field)
                if encrypted_value:
                    return FieldEncryption.decrypt(encrypted_value)
        return getattr(self, field_name, None)

class EncryptionValidator:
    """
    Utility class for validating encryption implementation
    """
    
    @staticmethod
    def test_encryption():
        """Test encryption/decryption functionality"""
        test_data = [
            "test@example.com",
            "1234567890",
            "123 Main Street, City, Country",
            "John Doe",
            "secret_mfa_key_12345"
        ]
        
        results = []
        for data in test_data:
            try:
                encrypted = FieldEncryption.encrypt(data)
                decrypted = FieldEncryption.decrypt(encrypted)
                success = data == decrypted
                results.append({
                    'original': data,
                    'encrypted': encrypted[:20] + "..." if len(encrypted) > 20 else encrypted,
                    'decrypted': decrypted,
                    'success': success
                })
            except Exception as e:
                results.append({
                    'original': data,
                    'error': str(e),
                    'success': False
                })
        
        return results
    
    @staticmethod
    def validate_model_encryption(model_instance, encrypted_fields):
        """Validate that specified fields are properly encrypted in a model instance"""
        validation_results = {}
        
        for field_name in encrypted_fields:
            encrypted_field_name = f"_{field_name}_encrypted"
            
            # Check if encrypted field exists
            has_encrypted_field = hasattr(model_instance, encrypted_field_name)
            encrypted_value = getattr(model_instance, encrypted_field_name, None) if has_encrypted_field else None
            
            # Check if original field is cleared (should be None or empty)
            original_value = getattr(model_instance, field_name, None)
            
            validation_results[field_name] = {
                'has_encrypted_field': has_encrypted_field,
                'encrypted_value_exists': bool(encrypted_value),
                'original_field_cleared': not bool(original_value),
                'can_decrypt': False
            }
            
            # Test decryption if encrypted value exists
            if encrypted_value:
                try:
                    decrypted = FieldEncryption.decrypt(encrypted_value)
                    validation_results[field_name]['can_decrypt'] = True
                    validation_results[field_name]['decrypted_length'] = len(decrypted) if decrypted else 0
                except:
                    validation_results[field_name]['can_decrypt'] = False
        
        return validation_results
