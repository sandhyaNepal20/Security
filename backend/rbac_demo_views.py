from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .role_helpers import (
    admin_required, staff_required, moderator_required, 
    check_permission, get_user_role, assign_role
)
from .models import User, Product, UserRole
from .security_utils import SecurityUtils

# RBAC Demo Views - These demonstrate how Role-Based Access Control works

@admin_required
def admin_dashboard(request):
    """Admin-only dashboard - Only ADMIN role can access"""
    total_users = User.objects.count()
    total_products = Product.objects.count()
    
    # Get role distribution
    role_stats = {}
    for role in ['ADMIN', 'STAFF', 'MODERATOR', 'CUSTOMER']:
        count = UserRole.objects.filter(role=role).count()
        role_stats[role] = count
    
    context = {
        'total_users': total_users,
        'total_products': total_products,
        'role_stats': role_stats,
        'user_role': get_user_role(request.user)
    }
    return render(request, 'rbac_demo/admin_dashboard.html', context)

@staff_required
def manage_products(request):
    """Staff and Admin can manage products"""
    if not check_permission(request.user, 'manage_products'):
        messages.error(request, "You don't have permission to manage products.")
        return redirect('home')
    
    products = Product.objects.all()[:10]  # Show first 10 products
    
    context = {
        'products': products,
        'user_role': get_user_role(request.user),
        'can_edit': check_permission(request.user, 'edit_products'),
        'can_delete': check_permission(request.user, 'delete_all')
    }
    return render(request, 'rbac_demo/manage_products.html', context)

@staff_required
def view_security_logs(request):
    """Staff and Admin can view security logs"""
    if not check_permission(request.user, 'view_logs'):
        messages.error(request, "You don't have permission to view logs.")
        return redirect('home')
    
    # Get recent security activities (this would be from your SecurityUtils logging)
    # For demo purposes, we'll show a simple message
    
    context = {
        'user_role': get_user_role(request.user),
        'message': 'Security logs would be displayed here. Only STAFF and ADMIN can access this.'
    }
    return render(request, 'rbac_demo/security_logs.html', context)

@moderator_required
def moderate_content(request):
    """Moderator, Staff, and Admin can moderate content"""
    if not check_permission(request.user, 'moderate_content'):
        messages.error(request, "You don't have permission to moderate content.")
        return redirect('home')
    
    context = {
        'user_role': get_user_role(request.user),
        'message': 'Content moderation panel. MODERATOR, STAFF, and ADMIN can access this.'
    }
    return render(request, 'rbac_demo/moderate_content.html', context)

@login_required
def rbac_demo_home(request):
    """Demo page showing what each role can access"""
    user_role = get_user_role(request.user)
    
    # Check what the current user can access
    permissions = {
        'can_admin': check_permission(request.user, 'manage_users'),
        'can_manage_products': check_permission(request.user, 'manage_products'),
        'can_view_logs': check_permission(request.user, 'view_logs'),
        'can_moderate': check_permission(request.user, 'moderate_content'),
        'can_purchase': check_permission(request.user, 'purchase')
    }
    
    context = {
        'user_role': user_role,
        'permissions': permissions
    }
    return render(request, 'rbac_demo/rbac_home.html', context)

@admin_required
def change_user_role(request):
    """Admin can change user roles - demonstrates role assignment"""
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        new_role = request.POST.get('role')
        
        try:
            user = User.objects.get(id=user_id)
            if assign_role(user, new_role):
                messages.success(request, f"Successfully changed {user.username}'s role to {new_role}")
                
                # Log the role change
                SecurityUtils.log_activity(
                    request.user, 'ROLE_CHANGE',
                    f'Changed user {user.username} role to {new_role}',
                    request, True
                )
            else:
                messages.error(request, "Invalid role specified")
        except User.DoesNotExist:
            messages.error(request, "User not found")
    
    # Get all users with their roles
    users = User.objects.all()
    users_with_roles = []
    for user in users:
        users_with_roles.append({
            'user': user,
            'role': get_user_role(user)
        })
    
    context = {
        'users_with_roles': users_with_roles,
        'available_roles': ['ADMIN', 'STAFF', 'MODERATOR', 'CUSTOMER']
    }
    return render(request, 'rbac_demo/change_roles.html', context)
