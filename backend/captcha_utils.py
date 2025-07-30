import random
import hashlib
import time
from django.core.cache import cache
from django.utils import timezone

class SimpleBotProtection:
    """
    Simple "I am not a robot" checkbox CAPTCHA for spam and bot protection
    Uses challenge-response mechanism to verify human interaction
    """
    
    # Bot protection settings
    CHALLENGE_TIMEOUT = 300  # 5 minutes
    MAX_FAILURES_BEFORE_CAPTCHA = 2  # Show CAPTCHA after 2 failed attempts
    
    @staticmethod
    def generate_challenge():
        """Generate a simple challenge token for bot protection"""
        # Create a unique challenge token
        timestamp = str(int(time.time()))
        random_data = str(random.randint(100000, 999999))
        challenge_token = hashlib.sha256(f"{timestamp}_{random_data}".encode()).hexdigest()[:16]
        
        # Store challenge in cache with expiration
        cache_key = f"bot_protection_{challenge_token}"
        cache.set(cache_key, {
            'created_at': timestamp,
            'verified': False
        }, SimpleBotProtection.CHALLENGE_TIMEOUT)
        
        return challenge_token
    
    @staticmethod
    def verify_challenge(challenge_token, user_verified=True):
        """Verify the bot protection challenge"""
        if not challenge_token:
            return False
            
        cache_key = f"bot_protection_{challenge_token}"
        challenge_data = cache.get(cache_key)
        
        if not challenge_data:
            return False  # Challenge expired or invalid
            
        if user_verified:
            # Mark challenge as verified
            challenge_data['verified'] = True
            cache.set(cache_key, challenge_data, SimpleBotProtection.CHALLENGE_TIMEOUT)
            return True
            
        return False
    
    @staticmethod
    def is_captcha_required(request):
        """Check if CAPTCHA is required for this IP address"""
        client_ip = SimpleBotProtection.get_client_ip(request)
        failure_key = f"login_failures_{client_ip}"
        failure_count = cache.get(failure_key, 0)
        return failure_count >= SimpleBotProtection.MAX_FAILURES_BEFORE_CAPTCHA
    
    @staticmethod
    def record_login_failure(request):
        """Record a login failure for this IP"""
        client_ip = SimpleBotProtection.get_client_ip(request)
        failure_key = f"login_failures_{client_ip}"
        failure_count = cache.get(failure_key, 0) + 1
        cache.set(failure_key, failure_count, SimpleBotProtection.CHALLENGE_TIMEOUT)
    
    @staticmethod
    def clear_login_failures(request):
        """Clear login failures for this IP after successful login"""
        client_ip = SimpleBotProtection.get_client_ip(request)
        failure_key = f"login_failures_{client_ip}"
        cache.delete(failure_key)
    
    @staticmethod
    def get_client_ip(request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
