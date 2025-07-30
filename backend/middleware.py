from django.shortcuts import redirect
from django.contrib import messages
from django.urls import reverse
from .session_security import SessionSecurity

class SessionSecurityMiddleware:
    """
    Middleware to enforce session security policies
    - Validates session security on every request
    - Handles session timeouts and hijacking detection
    - Applies secure session headers
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Only validate session security if user attribute exists (after auth middleware)
        if hasattr(request, 'user'):
            if not SessionSecurity.validate_session_security(request):
                # Session validation failed, redirect to login
                if request.path not in [reverse('login'), reverse('home'), '/']:
                    return redirect('login')
        
        response = self.get_response(request)
        
        # Apply secure session headers
        self._apply_secure_headers(response)
        
        return response
    
    def _apply_secure_headers(self, response):
        """Apply secure headers to protect sessions"""
        
        # Prevent session fixation attacks
        response['X-Frame-Options'] = 'DENY'
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-XSS-Protection'] = '1; mode=block'
        
        # Strict Transport Security (HTTPS enforcement)
        response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Content Security Policy
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        
        # Referrer Policy
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Cache control for sensitive pages
        if hasattr(response, 'context') and response.context:
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
