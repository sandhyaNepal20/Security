from .models import UserRole
from django.shortcuts import redirect
from django.contrib import messages
from django.http import HttpResponseForbidden
from functools import wraps

def get_user_role(user):
    """Get user's role - simple helper function"""
    try:
        return user.role.role
    except UserRole.DoesNotExist:
        return 'CUSTOMER'

def is_admin(user):
    """Check if user is admin"""
    return get_user_role(user) == 'ADMIN'

def is_staff(user):
    """Check if user is staff or admin"""
    role = get_user_role(user)
    return role in ['ADMIN', 'STAFF']

def is_moderator(user):
    """Check if user is moderator, staff, or admin"""
    role = get_user_role(user)
    return role in ['ADMIN', 'STAFF', 'MODERATOR']

def can_access_admin(user):
    """Simple check for admin access"""
    return is_admin(user)

def can_manage_products(user):
    """Check if user can manage products"""
    return is_staff(user)

def can_view_logs(user):
    """Check if user can view security logs"""
    return is_staff(user)

# RBAC Decorators for Access Control
def require_role(required_roles):
    """Decorator to require specific roles for view access"""
    def decorator(view_func):
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                messages.error(request, "Please log in to access this page.")
                return redirect('login')
            
            user_role = get_user_role(request.user)
            if user_role not in required_roles:
                messages.error(request, f"Access denied. Required role: {', '.join(required_roles)}")
                return HttpResponseForbidden("<h1>403 Forbidden</h1><p>You don't have permission to access this resource.</p>")
            
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator

def admin_required(view_func):
    """Decorator for admin-only views"""
    return require_role(['ADMIN'])(view_func)

def staff_required(view_func):
    """Decorator for staff and admin views"""
    return require_role(['ADMIN', 'STAFF'])(view_func)

def moderator_required(view_func):
    """Decorator for moderator, staff, and admin views"""
    return require_role(['ADMIN', 'STAFF', 'MODERATOR'])(view_func)

# Simple role assignment function
def assign_role(user, role):
    """Assign role to user"""
    if role in ['ADMIN', 'STAFF', 'MODERATOR', 'CUSTOMER']:
        user_role, created = UserRole.objects.get_or_create(user=user)
        user_role.role = role
        user_role.save()
        return True
    return False

# Permission checking functions
def check_permission(user, action):
    """Check if user has permission for specific action"""
    user_role = get_user_role(user)
    
    permissions = {
        'ADMIN': ['view_all', 'edit_all', 'delete_all', 'manage_users', 'view_logs', 'manage_products'],
        'STAFF': ['view_products', 'edit_products', 'view_logs', 'manage_products'],
        'MODERATOR': ['view_products', 'moderate_content'],
        'CUSTOMER': ['view_products', 'purchase']
    }
    
    return action in permissions.get(user_role, [])
