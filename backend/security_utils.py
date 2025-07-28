import re
import hashlib
from datetime import datetime, timedelta
from django.contrib.auth.hashers import check_password, make_password
from django.utils import timezone
from django.contrib.auth.models import User
from .models import PasswordHistory, UserSecuritySettings, ActivityLog
import secrets
import string

class PasswordValidator:
    """Comprehensive password validation and security utilities"""
    
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    PASSWORD_HISTORY_COUNT = 5  # Prevent reuse of last 5 passwords
    PASSWORD_EXPIRY_DAYS = 90   # Force password change every 90 days
    
    @staticmethod
    def validate_password_strength(password):
        """
        Validate password against security requirements
        Returns: (is_valid, errors, strength_score)
        """
        errors = []
        strength_score = 0
        
        # Length check
        if len(password) < PasswordValidator.MIN_LENGTH:
            errors.append(f"Password must be at least {PasswordValidator.MIN_LENGTH} characters long")
        elif len(password) >= 12:
            strength_score += 2
        else:
            strength_score += 1
            
        if len(password) > PasswordValidator.MAX_LENGTH:
            errors.append(f"Password must not exceed {PasswordValidator.MAX_LENGTH} characters")
            
        # Complexity checks
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        else:
            strength_score += 1
            
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        else:
            strength_score += 1
            
        if not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        else:
            strength_score += 1
            
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        else:
            strength_score += 1
            
        # Additional strength checks
        if len(set(password)) / len(password) > 0.7:  # Character diversity
            strength_score += 1
            
        # Common patterns check
        common_patterns = ['123', 'abc', 'qwe', 'password', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            errors.append("Password contains common patterns")
            strength_score -= 1
            
        is_valid = len(errors) == 0
        strength_score = max(0, min(10, strength_score))  # Clamp between 0-10
        
        return is_valid, errors, strength_score
    
    @staticmethod
    def get_strength_label(score):
        """Convert numeric score to human-readable strength label"""
        if score <= 3:
            return "Weak"
        elif score <= 6:
            return "Medium"
        elif score <= 8:
            return "Strong"
        else:
            return "Very Strong"
    
    @staticmethod
    def check_password_reuse(user, new_password):
        """Check if password was used recently"""
        recent_passwords = PasswordHistory.objects.filter(
            user=user
        ).order_by('-created_at')[:PasswordValidator.PASSWORD_HISTORY_COUNT]
        
        for pwd_history in recent_passwords:
            if check_password(new_password, pwd_history.password_hash):
                return False, f"Password was used recently. Please choose a different password."
        
        return True, ""
    
    @staticmethod
    def save_password_history(user, password):
        """Save password to history"""
        PasswordHistory.objects.create(
            user=user,
            password_hash=make_password(password)
        )
        
        # Keep only recent passwords
        old_passwords = PasswordHistory.objects.filter(
            user=user
        ).order_by('-created_at')[PasswordValidator.PASSWORD_HISTORY_COUNT:]
        
        for old_pwd in old_passwords:
            old_pwd.delete()
    
    @staticmethod
    def is_password_expired(user):
        """Check if user's password has expired"""
        try:
            security_settings = user.security_settings
            expiry_date = security_settings.password_last_changed + timedelta(
                days=PasswordValidator.PASSWORD_EXPIRY_DAYS
            )
            return timezone.now() > expiry_date
        except UserSecuritySettings.DoesNotExist:
            return True  # Force password change if no security settings

class SecurityUtils:
    """General security utilities"""
    
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30
    
    @staticmethod
    def get_client_ip(request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    @staticmethod
    def log_activity(user, action, description, request=None, success=True):
        """Log user activity"""
        ip_address = None
        user_agent = ""
        
        if request:
            ip_address = SecurityUtils.get_client_ip(request)
            user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        ActivityLog.objects.create(
            user=user,
            action=action,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success
        )
    
    @staticmethod
    def handle_failed_login(user, request):
        """Handle failed login attempt"""
        security_settings, created = UserSecuritySettings.objects.get_or_create(user=user)
        security_settings.failed_login_attempts += 1
        
        if security_settings.failed_login_attempts >= SecurityUtils.MAX_LOGIN_ATTEMPTS:
            # Lock account
            security_settings.account_locked_until = timezone.now() + timedelta(
                minutes=SecurityUtils.LOCKOUT_DURATION_MINUTES
            )
            SecurityUtils.log_activity(
                user, 'ACCOUNT_LOCKED', 
                f'Account locked due to {SecurityUtils.MAX_LOGIN_ATTEMPTS} failed login attempts',
                request, False
            )
        
        security_settings.save()
        SecurityUtils.log_activity(
            user, 'LOGIN_FAILED', 
            f'Failed login attempt ({security_settings.failed_login_attempts}/{SecurityUtils.MAX_LOGIN_ATTEMPTS})',
            request, False
        )
    
    @staticmethod
    def handle_successful_login(user, request):
        """Handle successful login"""
        security_settings, created = UserSecuritySettings.objects.get_or_create(user=user)
        security_settings.failed_login_attempts = 0  # Reset failed attempts
        security_settings.account_locked_until = None  # Unlock account
        security_settings.last_login_ip = SecurityUtils.get_client_ip(request)
        security_settings.save()
        
        SecurityUtils.log_activity(
            user, 'LOGIN', 
            f'Successful login from IP: {security_settings.last_login_ip}',
            request, True
        )
    
    @staticmethod
    def generate_mfa_secret():
        """Generate MFA secret key"""
        return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(32))
    
    @staticmethod
    def is_account_locked(user):
        """Check if user account is locked"""
        try:
            return user.security_settings.is_account_locked()
        except UserSecuritySettings.DoesNotExist:
            return False

class RateLimiter:
    """Rate limiting utilities"""
    
    @staticmethod
    def is_rate_limited(identifier, max_requests=10, window_minutes=15):
        """
        Simple rate limiting based on identifier (IP, user, etc.)
        Returns True if rate limited
        """
        # This is a basic implementation - in production, use Redis or similar
        from django.core.cache import cache
        
        key = f"rate_limit_{identifier}"
        current_time = timezone.now()
        window_start = current_time - timedelta(minutes=window_minutes)
        
        # Get current request count
        requests = cache.get(key, [])
        
        # Filter requests within the window
        recent_requests = [req_time for req_time in requests if req_time > window_start]
        
        if len(recent_requests) >= max_requests:
            return True
        
        # Add current request
        recent_requests.append(current_time)
        cache.set(key, recent_requests, timeout=window_minutes * 60)
        
        return False
