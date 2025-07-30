import hashlib
import time
from django.conf import settings
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.contrib.auth import logout
from django.contrib import messages
from django.shortcuts import redirect
from django.http import HttpResponseRedirect
from .security_utils import SecurityUtils
import secrets
import string

class SessionSecurity:
    """
    Session Management Security Features
    - Secure session creation and handling
    - Session expiration policies
    - Session hijacking protection
    - Secure session headers
    """
    
    # Session security settings
    SESSION_TIMEOUT_MINUTES = 30  # Auto logout after 30 minutes of inactivity
    ABSOLUTE_SESSION_TIMEOUT_HOURS = 8  # Force logout after 8 hours regardless of activity
    MAX_SESSIONS_PER_USER = 3  # Maximum concurrent sessions per user
    
    @staticmethod
    def create_secure_session(request, user):
        """Create a secure session with enhanced security features"""
        
        # Generate secure session key
        session_key = SessionSecurity._generate_secure_session_key()
        
        # Set session data with security metadata
        request.session['user_id'] = user.id
        request.session['session_created'] = time.time()
        request.session['last_activity'] = time.time()
        request.session['ip_address'] = SecurityUtils.get_client_ip(request)
        request.session['user_agent_hash'] = SessionSecurity._hash_user_agent(request)
        request.session['session_token'] = session_key
        
        # Set secure session configuration
        request.session.set_expiry(SessionSecurity.SESSION_TIMEOUT_MINUTES * 60)
        
        # Log session creation
        SecurityUtils.log_activity(
            user, 'SESSION_CREATED',
            f'Secure session created for user {user.username}',
            request, True
        )
        
        # Cleanup old sessions for this user
        SessionSecurity._cleanup_old_sessions(user)
        
        return session_key
    
    @staticmethod
    def validate_session_security(request):
        """Validate session security and detect potential hijacking"""
        
        if not request.user.is_authenticated:
            return True  # No validation needed for anonymous users
        
        # Check if session exists and is valid
        if 'session_created' not in request.session:
            return SessionSecurity._handle_invalid_session(request, 'Missing session metadata')
        
        # Check session timeout (inactivity)
        last_activity = request.session.get('last_activity', 0)
        if time.time() - last_activity > (SessionSecurity.SESSION_TIMEOUT_MINUTES * 60):
            return SessionSecurity._handle_session_timeout(request, 'Session timeout due to inactivity')
        
        # Check absolute session timeout
        session_created = request.session.get('session_created', 0)
        if time.time() - session_created > (SessionSecurity.ABSOLUTE_SESSION_TIMEOUT_HOURS * 3600):
            return SessionSecurity._handle_session_timeout(request, 'Absolute session timeout reached')
        
        # Check IP address consistency (detect session hijacking)
        stored_ip = request.session.get('ip_address')
        current_ip = SecurityUtils.get_client_ip(request)
        if stored_ip and stored_ip != current_ip:
            return SessionSecurity._handle_suspicious_activity(request, f'IP address changed from {stored_ip} to {current_ip}')
        
        # Check User-Agent consistency (detect session hijacking)
        stored_ua_hash = request.session.get('user_agent_hash')
        current_ua_hash = SessionSecurity._hash_user_agent(request)
        if stored_ua_hash and stored_ua_hash != current_ua_hash:
            return SessionSecurity._handle_suspicious_activity(request, 'User-Agent changed during session')
        
        # Update last activity timestamp
        request.session['last_activity'] = time.time()
        
        return True
    
    @staticmethod
    def _generate_secure_session_key():
        """Generate a cryptographically secure session key"""
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(32))
    
    @staticmethod
    def _hash_user_agent(request):
        """Create a hash of the user agent for consistency checking"""
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        return hashlib.sha256(user_agent.encode()).hexdigest()[:16]
    
    @staticmethod
    def _handle_invalid_session(request, reason):
        """Handle invalid session scenarios"""
        if request.user.is_authenticated:
            SecurityUtils.log_activity(
                request.user, 'SESSION_INVALID',
                f'Invalid session detected: {reason}',
                request, False
            )
            logout(request)
        return False
    
    @staticmethod
    def _handle_session_timeout(request, reason):
        """Handle session timeout scenarios"""
        if request.user.is_authenticated:
            SecurityUtils.log_activity(
                request.user, 'SESSION_TIMEOUT',
                f'Session timeout: {reason}',
                request, True
            )
            logout(request)
            messages.warning(request, "Your session has expired. Please log in again.")
        return False
    
    @staticmethod
    def _handle_suspicious_activity(request, reason):
        """Handle suspicious session activity (potential hijacking)"""
        if request.user.is_authenticated:
            SecurityUtils.log_activity(
                request.user, 'SESSION_HIJACK_ATTEMPT',
                f'Suspicious session activity: {reason}',
                request, False
            )
            logout(request)
            messages.error(request, "Suspicious activity detected. You have been logged out for security.")
        return False
    
    @staticmethod
    def _cleanup_old_sessions(user):
        """Remove old sessions for a user to enforce session limits"""
        try:
            # Get all sessions for this user
            user_sessions = []
            for session in Session.objects.all():
                session_data = session.get_decoded()
                if session_data.get('user_id') == user.id:
                    user_sessions.append((session, session_data.get('session_created', 0)))
            
            # Sort by creation time (newest first)
            user_sessions.sort(key=lambda x: x[1], reverse=True)
            
            # Remove excess sessions
            if len(user_sessions) > SessionSecurity.MAX_SESSIONS_PER_USER:
                for session, _ in user_sessions[SessionSecurity.MAX_SESSIONS_PER_USER:]:
                    session.delete()
                    SecurityUtils.log_activity(
                        user, 'SESSION_CLEANUP',
                        'Old session removed due to session limit',
                        None, True
                    )
        except Exception as e:
            # Log error but don't fail the login process
            SecurityUtils.log_activity(
                user, 'SESSION_CLEANUP_ERROR',
                f'Error during session cleanup: {str(e)}',
                None, False
            )
    
    @staticmethod
    def force_logout_all_sessions(user):
        """Force logout all sessions for a specific user"""
        try:
            sessions_removed = 0
            for session in Session.objects.all():
                session_data = session.get_decoded()
                if session_data.get('user_id') == user.id:
                    session.delete()
                    sessions_removed += 1
            
            SecurityUtils.log_activity(
                user, 'ALL_SESSIONS_TERMINATED',
                f'All sessions terminated for user {user.username} ({sessions_removed} sessions)',
                None, True
            )
            return sessions_removed
        except Exception as e:
            SecurityUtils.log_activity(
                user, 'SESSION_TERMINATION_ERROR',
                f'Error terminating sessions: {str(e)}',
                None, False
            )
            return 0
    
    @staticmethod
    def get_active_sessions_count(user):
        """Get count of active sessions for a user"""
        try:
            count = 0
            for session in Session.objects.all():
                session_data = session.get_decoded()
                if session_data.get('user_id') == user.id:
                    count += 1
            return count
        except Exception:
            return 0
    
    @staticmethod
    def get_session_info(request):
        """Get current session information"""
        if not request.user.is_authenticated:
            return None
        
        session_created = request.session.get('session_created', 0)
        last_activity = request.session.get('last_activity', 0)
        
        return {
            'session_age_minutes': (time.time() - session_created) / 60 if session_created else 0,
            'inactive_minutes': (time.time() - last_activity) / 60 if last_activity else 0,
            'ip_address': request.session.get('ip_address', 'Unknown'),
            'session_token': request.session.get('session_token', 'Unknown'),
            'expires_in_minutes': SessionSecurity.SESSION_TIMEOUT_MINUTES - ((time.time() - last_activity) / 60) if last_activity else 0
        }
