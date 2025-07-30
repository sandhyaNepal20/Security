from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.hashers import make_password
from django.contrib.auth import update_session_auth_hash
from django.core.mail import send_mail
from django.utils import timezone
from .models import UserProfile, Product, Category, UserSecuritySettings, PasswordHistory, UserRole, Payment
from .security_utils import SecurityUtils, PasswordValidator, RateLimiter
from .captcha_utils import SimpleBotProtection
from .role_helpers import admin_required, staff_required, moderator_required, check_permission, get_user_role
from .session_security import SessionSecurity
from .encryption_utils import EncryptionValidator, FieldEncryption
import random
import json
from django.conf import settings

def home_view(request):
    products = Product.objects.all()[:4]  # Fetch only top 4 for homepage
    categories = Category.objects.all()  # corrected variable name to plural 'categories'

    return render(request, 'home.html', {'products': products, 'categories': categories})

    return render(request, 'home.html', {'products': products})
from django.contrib.auth import logout
from django.shortcuts import redirect

def logout_view(request):
    if request.user.is_authenticated:
        # Log logout activity
        SecurityUtils.log_activity(
            request.user, 'LOGOUT', 
            'User logged out',
            request, True
        )
    logout(request)
    return redirect('home')
def wishlist_view(request):
    return render(request, 'wishlist.html')
def beforecart_view(request):
    return render(request, 'beforecart.html')
def cart_view(request):
    return render(request, 'cart.html')
def login_view(request):
    # Always show captcha for enhanced security
    show_captcha = True
    challenge_token = SimpleBotProtection.generate_challenge()
    
    # Check for account lockout status on page load
    account_locked_info = None
    if request.method == 'GET':
        # Check if there's an email in the session or query params to check lockout status
        email = request.GET.get('email', '')
        if email:
            try:
                user = User.objects.get(email=email)
                if SecurityUtils.is_account_locked(user):
                    remaining_time = SecurityUtils.get_lockout_remaining_time(user)
                    account_locked_info = {
                        'email': email,
                        'remaining_time': remaining_time,
                        'message': f"🔒 Account for {email} is temporarily locked. Please try again in {remaining_time} minute(s)."
                    }
            except User.DoesNotExist:
                pass
    
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        
        # Rate limiting check
        client_ip = SecurityUtils.get_client_ip(request)
        if RateLimiter.is_rate_limited(f"login_{client_ip}", max_requests=10, window_minutes=15):
            messages.error(request, "Too many login attempts from this IP address. Please try again later.")
            return redirect('login')
        
        # Bot protection verification - always required now
        challenge_token_post = request.POST.get('challenge_token')
        robot_check = request.POST.get('robot_check')
        
        # Verify captcha is checked and token is valid
        if not robot_check:
            messages.error(request, "Please check the 'I am not a robot' box to continue.")
            SimpleBotProtection.record_login_failure(request)
            return redirect('login')
            
        if not challenge_token_post or not SimpleBotProtection.verify_challenge(challenge_token_post, user_verified=True):
            messages.error(request, "Captcha verification failed. Please refresh the page and try again.")
            SimpleBotProtection.record_login_failure(request)
            return redirect('login')
        
        # Validate email and password are provided
        if not email or not password:
            messages.error(request, "Please provide both email and password.")
            return redirect('login')
        
        try:
            user = User.objects.get(email=email)
            
            # Check if account is locked BEFORE attempting password check
            if SecurityUtils.is_account_locked(user):
                remaining_time = SecurityUtils.get_lockout_remaining_time(user)
                messages.error(request, f"🔒 Account is temporarily locked due to multiple failed login attempts. Please try again in {remaining_time} minute(s).")
                # Redirect with email parameter to show lockout status on page reload
                return redirect(f'/login/?email={email}')
            
            # Get current failed attempts count for messaging
            try:
                security_settings = user.security_settings
                current_attempts = security_settings.failed_login_attempts
            except UserSecuritySettings.DoesNotExist:
                current_attempts = 0
            
            # Check password
            if user.check_password(password):
                # Check if password has expired
                if PasswordValidator.is_password_expired(user):
                    request.session['force_password_change'] = True
                    request.session['user_id'] = user.id
                    messages.warning(request, "Your password has expired. Please change it to continue.")
                    return redirect('change_password')
                
                # Create secure session
                SessionSecurity.create_secure_session(request, user)
                
                # Reset failed login attempts and clear bot protection requirement
                SecurityUtils.reset_failed_attempts(user)
                SimpleBotProtection.clear_login_failures(request)
                
                # Log successful login
                SecurityUtils.log_activity(
                    user, 'LOGIN', 
                    f'Successful login from {client_ip}',
                    request, True
                )
                
                login(request, user)
                messages.success(request, f"Welcome back, {user.first_name}!")
                return redirect('home')
            else:
                # Handle failed login with detailed messaging
                SecurityUtils.handle_failed_login(user, request)
                SimpleBotProtection.record_login_failure(request)
                
                # Get updated failed attempts count after increment
                try:
                    security_settings = user.security_settings
                    new_attempts = security_settings.failed_login_attempts
                    remaining_attempts = SecurityUtils.MAX_LOGIN_ATTEMPTS - new_attempts
                    
                    if new_attempts >= SecurityUtils.MAX_LOGIN_ATTEMPTS:
                        # Account just got locked - redirect with email to show lockout status
                        messages.error(request, f"🔒 Account locked! Too many failed login attempts ({SecurityUtils.MAX_LOGIN_ATTEMPTS}/{SecurityUtils.MAX_LOGIN_ATTEMPTS}). Your account has been temporarily locked for {SecurityUtils.LOCKOUT_DURATION_MINUTES} minutes for security.")
                        return redirect(f'/login/?email={email}')
                    elif remaining_attempts <= 2:
                        # Warning when close to lockout
                        messages.error(request, f"⚠️ Invalid email or password. Warning: {remaining_attempts} attempt(s) remaining before account lockout.")
                    else:
                        # Regular failed login message
                        messages.error(request, f"❌ Invalid email or password. {remaining_attempts} attempt(s) remaining.")
                        
                except UserSecuritySettings.DoesNotExist:
                    messages.error(request, "❌ Invalid email or password.")
                
                return redirect('login')
                
        except User.DoesNotExist:
            # Log failed login attempt for non-existent user
            SecurityUtils.log_activity(
                None, 'LOGIN_FAILED', 
                f'Login attempt for non-existent email: {email}',
                request, False
            )
            SimpleBotProtection.record_login_failure(request)
            messages.error(request, "❌ Invalid email or password. Please check your credentials and try again.")
            return redirect('login')
    
    context = {
        'show_captcha': show_captcha,
        'challenge_token': challenge_token,
        'account_locked_info': account_locked_info
    }
    
    return render(request, 'login.html', context)
def signup_view(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        phone = request.POST['phone']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        # Rate limiting check
        client_ip = SecurityUtils.get_client_ip(request)
        if RateLimiter.is_rate_limited(f"signup_{client_ip}", max_requests=5, window_minutes=60):
            messages.error(request, "Too many signup attempts. Please try again later.")
            return redirect('signup')

        # Validate password strength
        is_valid, errors, strength_score = PasswordValidator.validate_password_strength(password)
        if not is_valid:
            for error in errors:
                messages.error(request, error)
            return redirect('signup')

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('signup')

        if User.objects.filter(username=email).exists():
            messages.error(request, "Email already registered.")
            return redirect('signup')

        # Create user
        user = User.objects.create_user(username=email, email=email, password=password, first_name=name)
        user.save()

        # Create UserProfile and save phone
        profile = UserProfile.objects.create(user=user, phone=phone)
        profile.save()

        # Create UserSecuritySettings
        security_settings = UserSecuritySettings.objects.create(
            user=user,
            password_last_changed=timezone.now()
        )
        security_settings.save()

        # Create UserRole (default to CUSTOMER)
        user_role = UserRole.objects.create(user=user, role='CUSTOMER')
        user_role.save()

        # Save password to history
        PasswordValidator.save_password_history(user, password)

        # Log registration activity
        SecurityUtils.log_activity(
            user, 'REGISTRATION', 
            f'New user registered: {email}',
            request, True
        )

        messages.success(request, "Account created successfully. Please log in.")
        return redirect('login')

    return render(request, 'signup.html')

def password_reset_view(request):
    if request.method == 'POST':
        email = request.POST.get('email')

        # Rate limiting check for password reset attempts
        client_ip = SecurityUtils.get_client_ip(request)
        if RateLimiter.is_rate_limited(f"password_reset_{client_ip}", max_requests=3, window_minutes=60):
            messages.error(request, "Too many password reset attempts. Please try again later.")
            return redirect('password_reset')

        # Additional rate limiting per email to prevent targeting specific accounts
        if RateLimiter.is_rate_limited(f"password_reset_email_{email}", max_requests=2, window_minutes=30):
            messages.error(request, "Too many reset attempts for this email. Please try again later.")
            return redirect('password_reset')

        # Generate OTP
        otp = str(random.randint(100000, 999999))
        request.session['reset_email'] = email
        request.session['reset_otp'] = otp

        # Log password reset attempt
        SecurityUtils.log_activity(
            None, 'PASSWORD_RESET_REQUESTED', 
            f'Password reset requested for email: {email}',
            request, True
        )

        # Send email
        subject = 'MeroAakar Password Reset OTP'
        message = f'Your OTP for resetting your password is: {otp}'
        from_email = None  # Uses DEFAULT_FROM_EMAIL in settings
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list, fail_silently=False)

        return redirect('reset_code')

    return render(request, 'password_reset.html')
def reset_code_view(request):
    if request.method == 'POST':
        user_otp = request.POST.get('otp')
        actual_otp = request.session.get('reset_otp')

        if user_otp == actual_otp:
            return redirect('set_new_password')  # create this view/page for new password input
        else:
            return render(request, 'resetcode.html', {'error': 'Invalid OTP. Try again.'})

    return render(request, 'resetcode.html')

def set_new_password_view(request):
    if request.method == 'POST':
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if password1 != password2:
            return render(request, 'setnewpassword.html', {'error': 'Passwords do not match'})

        email = request.session.get('reset_email')
        if not email:
            return redirect('password_reset')  # Start over if no email in session

        try:
            user = User.objects.get(email=email)
            user.password = make_password(password1)
            user.save()

            # Clear session
            request.session.flush()

            return render(request, 'setnewpassword.html', {'success': 'Password changed successfully!'})
        except User.DoesNotExist:
            return render(request, 'setnewpassword.html', {'error': 'User not found'})

    return render(request, 'setnewpassword.html')
def search_product_view(request):
    products = Product.objects.all()
    categories = Category.objects.all()  # corrected variable name to plural 'categories'

    for product in products:
        try:
            product.color_options = json.loads(product.color_options or "[]")
        except:
            product.color_options = []
    return render(request, 'searchproduct.html', {'products': products, 'categories': categories})

@login_required
def account_view(request):
    user = request.user
    try:
        phone = user.userprofile.phone
    except UserProfile.DoesNotExist:
        phone = "Not Provided"
    
    # Get user role information using RBAC helpers
    user_role = get_user_role(user)
    
    # Check permissions for different actions
    permissions = {
        'can_manage_products': check_permission(user, 'manage_products'),
        'can_view_logs': check_permission(user, 'view_logs'),
        'can_manage_users': check_permission(user, 'manage_users'),
        'is_admin': user_role == 'ADMIN',
        'is_staff': user_role in ['ADMIN', 'STAFF'],
    }

    context = {
        'name': user.first_name,
        'email': user.email,
        'phone': phone,
        'user_role': user_role,
        'permissions': permissions,
    }
    return render(request, 'account.html', context)

# RBAC Protected Views - Demonstrating Role-Based Access Control

@admin_required
def admin_panel(request):
    """Admin-only panel - Only users with ADMIN role can access"""
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
    return render(request, 'admin_panel.html', context)

@staff_required
def staff_dashboard(request):
    """Staff dashboard - Only STAFF and ADMIN roles can access"""
    if not check_permission(request.user, 'manage_products'):
        messages.error(request, "You don't have permission to access the staff dashboard.")
        return redirect('account')
    
    products = Product.objects.all()[:10]  # Show first 10 products
    
    context = {
        'products': products,
        'user_role': get_user_role(request.user),
        'can_edit': check_permission(request.user, 'edit_products'),
        'can_delete': check_permission(request.user, 'delete_all')
    }
    return render(request, 'staff_dashboard.html', context)

@staff_required
def view_security_logs(request):
    """Security logs view - Only STAFF and ADMIN can access"""
    if not check_permission(request.user, 'view_logs'):
        messages.error(request, "You don't have permission to view security logs.")
        return redirect('account')
    
    # Log this access
    SecurityUtils.log_activity(
        request.user, 'SECURITY_LOGS_ACCESSED',
        'User accessed security logs',
        request, True
    )
    
    context = {
        'user_role': get_user_role(request.user),
        'message': 'Security logs access granted. Only STAFF and ADMIN roles can view this page.'
    }
    return render(request, 'security_logs.html', context)

@moderator_required
def moderate_content(request):
    """Content moderation - MODERATOR, STAFF, and ADMIN can access"""
    if not check_permission(request.user, 'moderate_content'):
        messages.error(request, "You don't have permission to moderate content.")
        return redirect('account')
    
    context = {
        'user_role': get_user_role(request.user),
        'message': 'Content moderation panel. MODERATOR, STAFF, and ADMIN roles can access this.'
    }
    return render(request, 'moderate_content.html', context)

@admin_required
def manage_user_roles(request):
    """User role management - Only ADMIN can access"""
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        new_role = request.POST.get('role')
        
        try:
            user = User.objects.get(id=user_id)
            from .role_helpers import assign_role
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
    return render(request, 'manage_roles.html', context)

# Session Management Views - Demonstrating Session Security Features

@login_required
def session_info(request):
    """Display current session information and security status"""
    session_info = SessionSecurity.get_session_info(request)
    active_sessions_count = SessionSecurity.get_active_sessions_count(request.user)
    
    context = {
        'session_info': session_info,
        'active_sessions_count': active_sessions_count,
        'max_sessions_allowed': SessionSecurity.MAX_SESSIONS_PER_USER,
        'user_role': get_user_role(request.user)
    }
    return render(request, 'session_info.html', context)

@login_required
def terminate_all_sessions(request):
    """Terminate all sessions for the current user (except current one)"""
    if request.method == 'POST':
        sessions_terminated = SessionSecurity.force_logout_all_sessions(request.user)
        
        # Create a new secure session for the current user
        SessionSecurity.create_secure_session(request, request.user)
        
        messages.success(request, f"Successfully terminated {sessions_terminated} session(s). You remain logged in on this device.")
        
        # Log this security action
        SecurityUtils.log_activity(
            request.user, 'ALL_SESSIONS_TERMINATED_BY_USER',
            f'User manually terminated all sessions ({sessions_terminated} sessions)',
            request, True
        )
    
    return redirect('session_info')

@staff_required
def session_management_dashboard(request):
    """Staff dashboard for monitoring session security - STAFF and ADMIN only"""
    if not check_permission(request.user, 'view_logs'):
        messages.error(request, "You don't have permission to access session management.")
        return redirect('account')
    
    # Get session statistics
    from django.contrib.sessions.models import Session
    from django.contrib.auth.models import User
    
    total_sessions = Session.objects.count()
    total_users = User.objects.count()
    
    # Get users with multiple sessions
    users_with_multiple_sessions = []
    for user in User.objects.all():
        session_count = SessionSecurity.get_active_sessions_count(user)
        if session_count > 1:
            users_with_multiple_sessions.append({
                'user': user,
                'session_count': session_count
            })
    
    context = {
        'total_sessions': total_sessions,
        'total_users': total_users,
        'users_with_multiple_sessions': users_with_multiple_sessions,
        'session_timeout_minutes': SessionSecurity.SESSION_TIMEOUT_MINUTES,
        'max_sessions_per_user': SessionSecurity.MAX_SESSIONS_PER_USER,
        'user_role': get_user_role(request.user)
    }
    return render(request, 'session_management.html', context)

@admin_required
def force_user_logout(request):
    """Admin can force logout all sessions for any user"""
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        try:
            target_user = User.objects.get(id=user_id)
            sessions_terminated = SessionSecurity.force_logout_all_sessions(target_user)
            
            messages.success(request, f"Successfully terminated {sessions_terminated} session(s) for user {target_user.username}")
            
            # Log this admin action
            SecurityUtils.log_activity(
                request.user, 'ADMIN_FORCE_LOGOUT',
                f'Admin {request.user.username} terminated all sessions for user {target_user.username}',
                request, True
            )
        except User.DoesNotExist:
            messages.error(request, "User not found")
    
    return redirect('session_management_dashboard')

@login_required
def edit_profile_view(request):
    user = request.user
    profile, created = UserProfile.objects.get_or_create(user=user)

    if request.method == 'POST':
        full_name = request.POST.get('fullname')
        phone = request.POST.get('phone')

        user.first_name = full_name
        user.save()

        profile.phone = phone
        profile.save()

        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if current_password or new_password or confirm_password:
            if not user.check_password(current_password):
                messages.error(request, "Current password is incorrect.")
                return redirect('editprofile')

            if new_password != confirm_password:
                messages.error(request, "New passwords do not match.")
                return redirect('editprofile')

            user.set_password(new_password)
            user.save()
            update_session_auth_hash(request, user)
            messages.success(request, "Password updated successfully.")
        else:
            messages.success(request, "Profile updated successfully.")

      

    context = {
        'name': user.first_name,
        'email': user.email,
        'phone': profile.phone,
    }
    return render(request, 'editprofile.html', context)

def searchproduct_view(request):
    category_name = request.GET.get('type')  # Category from dropdown
    search_query = request.GET.get('q')  # Optional: from search bar

    categories = Category.objects.all().order_by('name')
    products = Product.objects.all()

  

    if category_name and category_name.lower() != "all":
        products = products.filter(category__name__iexact=category_name)

    for product in products:
        try:
            product.color_options = json.loads(product.color_options or "[]")
        except:
            product.color_options = []

    return render(request, 'searchproduct.html', {
        'products': products,
        'categories': categories,
        'selected_category': category_name,
        'search_query': search_query,
    })

# def customize_product_view(request, product_id):
#     product = get_object_or_404(Product, id=product_id)

#     thumbnails = []
#     for thumb in [product.thumbnail1, product.thumbnail2, product.thumbnail3, product.thumbnail4, product.thumbnail5]:
#         if thumb:
#             thumbnails.append(thumb.url)

#     try:
#         color_variants = json.loads(product.color_options or "[]")
#     except:
#         color_variants = []

#     return render(request, 'customize.html', {
#         'product': product,
#         'thumbnails': thumbnails,
#         'color_variants': color_variants,
#     })
def customize_product_view(request, product_id):
    product = get_object_or_404(Product, id=product_id)

    # Get thumbnails
    thumbnails = []
    for thumb in [product.thumbnail1, product.thumbnail2, product.thumbnail3, product.thumbnail4, product.thumbnail5]:
        if thumb:
            thumbnails.append(thumb.url)

    # Get color options
    try:
        color_variants = json.loads(product.color_options or "[]")
    except:
        color_variants = []

    # Related products by same category
    related_products = Product.objects.filter(category=product.category).exclude(id=product.id)[:4]

    return render(request, 'customize.html', {
        'product': product,
        'thumbnails': thumbnails,
        'color_variants': color_variants,
        'related_products': related_products,  # pass to template
    })


def cart_view(request):
    if request.user.is_authenticated:
        return render(request, 'cart.html')  # Authenticated users see their cart
    else:
        return render(request, 'beforecart.html')  # Guests see login prompt

def placeorder_view(request):
    product_id = request.GET.get('product_id')
    quantity = int(request.GET.get('quantity', 1))
    
    product = get_object_or_404(Product, pk=product_id)

    return render(request, 'placeorder.html', {
        'product': product,
        'quantity': quantity,
        'total_price': product.price * quantity,
    })

def add_to_save(request):
    if request.method == 'POST':
        product_id = request.POST.get('product_id')
        if product_id:
            product_id = int(product_id)
            # Get the current saved list from session
            saved = request.session.get('recently_viewed', [])

            # Add if not already saved
            if product_id not in saved:
                saved.insert(0, product_id)
                if len(saved) > 10:
                    saved = saved[:10]  # Keep only 10 items
                request.session['recently_viewed'] = saved

    return redirect('save')

def save_view(request):
    saved_ids = request.session.get('recently_viewed', [])
    products = Product.objects.filter(id__in=saved_ids)

    # To preserve order
    products = sorted(products, key=lambda x: saved_ids.index(x.id))

    return render(request, 'save.html', {'products': products})

# def contact_view(request):
#     if request.method == 'POST':
#         name = request.POST.get('name')
#         email = request.POST.get('email')
#         phone = request.POST.get('phone')
#         message = request.POST.get('message')

#         subject = f"New Contact Form Submission from {name}"
#         full_message = f"""
#         Name: {name}
#         Email: {email}
#         Phone: {phone}
#         Message: {message}
#         """

#         send_mail(
#             subject,
#             full_message,
#             'your_email@gmail.com',  # From email
#             ['meroaakar@gmail.com'],  # To email (or a list of recipients)
#             fail_silently=False,
#         )

#         messages.success(request, 'Your message has been sent successfully!')
#         return redirect('/')  # or render a thank-you page

#     return render(request, 'home.html')
@login_required
def upload_profile_picture(request):
    if request.method == 'POST' and request.FILES.get('profile_image'):
        profile = request.user.userprofile
        profile.profile_image = request.FILES['profile_image']
        profile.save()
    return redirect('account')  


def send_contact_email(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        message = request.POST.get('message')

        subject = f"New Contact Form Submission from {name}"
        body = f"""
        Name: {name}
        Email: {email}
        Phone: {phone}
        Message: {message}
        """

        send_mail(
            subject,
            body,
            email,  # from email (sender)
            ['sandhyanepal54@gmail.com'],  # to email (receiver)
            fail_silently=False,
        )

        messages.success(request, "Your message has been sent successfully!")
        return redirect('home')  # or wherever you want to redirect

    return redirect('home')
@csrf_exempt
def save_payment_details(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            print(f"Payment data received: {data}")  # Debug log

            # Check if user is authenticated
            if not request.user.is_authenticated:
                return JsonResponse({'status': 'error', 'message': 'User not authenticated'}, status=401)

            user = request.user
            product_id = data.get('product_id')
            
            # Validate required fields
            if not product_id:
                return JsonResponse({'status': 'error', 'message': 'Product ID is required'}, status=400)
            
            try:
                product = Product.objects.get(id=product_id)
            except Product.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Product not found'}, status=404)

            full_name = data.get('full_name', '').strip()
            phone = data.get('phone', '').strip()
            city = data.get('city', '').strip()
            address = data.get('address', '').strip()
            amount = data.get('amount')
            payment_method = data.get('payment_method', 'khalti')  # Default to khalti for backward compatibility

            # Validate required fields (common for both payment methods)
            if not all([full_name, phone, city, address, amount]):
                return JsonResponse({'status': 'error', 'message': 'All required fields must be filled'}, status=400)

            # Handle different payment methods
            if payment_method == 'stripe':
                payment_intent_id = data.get('payment_intent_id')
                if not payment_intent_id:
                    return JsonResponse({'status': 'error', 'message': 'Payment intent ID is required for Stripe'}, status=400)
                
                # Create payment record for Stripe (using khalti_token field to store payment_intent_id)
                payment = Payment.objects.create(
                    user=user,
                    product=product,
                    full_name=full_name,
                    phone=phone,
                    city=city,
                    address=address,
                    khalti_token=f"stripe:{payment_intent_id}",  # Store Stripe payment intent ID with prefix
                    amount=amount  # Amount is already in correct format for Stripe
                )
                print(f"Stripe payment created successfully: {payment.id}")
                
                # Send email confirmation for Stripe payment
                try:
                    quantity = data.get('quantity', 1)
                    subject = 'Your MeroAakar Order is Confirmed - Stripe Payment'
                    message = f"""
Hello {full_name},

Your order has been confirmed and payment processed successfully! 

Order Details:
------------------
Product: {product.name}
Quantity: {quantity}
Price per item: Rs. {product.price}
Total: Rs. {amount}
Payment Method: Stripe (Card Payment)
Payment ID: {payment_intent_id}

Shipping Address:
{full_name}
{phone}
{address}, {city}

We will process and deliver your order soon. Thank you for shopping with MeroAakar!

Best regards,
MeroAakar Team
"""
                    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
                    print(f"Stripe payment confirmation email sent to {user.email}")
                except Exception as email_error:
                    print(f"Failed to send email: {str(email_error)}")
                    # Don't fail the payment if email fails
            else:
                # Handle Khalti payment (existing logic)
                token = data.get('token')
                if not token:
                    return JsonResponse({'status': 'error', 'message': 'Khalti token is required'}, status=400)
                
                # Create payment record for Khalti
                payment = Payment.objects.create(
                    user=user,
                    product=product,
                    full_name=full_name,
                    phone=phone,
                    city=city,
                    address=address,
                    khalti_token=token,
                    amount=amount / 100  # Convert paisa to rupees for Khalti
                )
                print(f"Khalti payment created successfully: {payment.id}")
            
            return JsonResponse({'status': 'success', 'payment_id': payment.id})

        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON data'}, status=400)
        except Exception as e:
            print(f"Payment error: {str(e)}")  # Debug log
            return JsonResponse({'status': 'error', 'message': f'Payment processing failed: {str(e)}'}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required

@csrf_exempt
@login_required
def send_cod_email(request):
    if request.method == "POST":
        data = json.loads(request.body)

        user = request.user
        email = user.email
        full_name = user.first_name

        product_name = data.get("product_name")
        product_price = data.get("product_price")
        quantity = data.get("quantity")
        total = data.get("total")
        address = data.get("address")

        subject = 'Your MeroAakar Order is Confirmed (Cash on Delivery)'
        message = f"""
Hello {full_name},

Your order has been confirmed. 

Order Details:
------------------
Product: {product_name}
Quantity: {quantity}
Price per item: Rs. {product_price}
Total: Rs. {total}

Shipping Address:
{address}

We will deliver your order soon. Thank you for shopping with MeroAakar!

Best,
MeroAakar Team
"""

        send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'failed', 'message': 'Invalid request'})

import random
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import stripe
import os
# Set Stripe secret key
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
@csrf_exempt
def initiate_khalti_payment(request):
    if request.method == 'POST':
        amount = int(request.POST.get('amount')) * 100  # Khalti expects amount in paisa
        order_id = request.POST.get('order_id', 'ORD_' + str(random.randint(1000, 9999)))

        payload = {
            "return_url": request.build_absolute_uri('/payment-success/'),
            "website_url": "http://127.0.0.1:8000/",  # or your actual domain
            "amount": amount,
            "purchase_order_id": order_id,
            "purchase_order_name": "MeroAakar Order"
        }

        headers = {
            "Authorization": f"Key {settings.KHALTI_SECRET_KEY}"
        }

        response = requests.post("https://a.khalti.com/api/v2/epayment/initiate/", json=payload, headers=headers)

        if response.status_code == 200:
            return JsonResponse(response.json())
        else:
            return JsonResponse({'error': 'Failed to initiate payment'}, status=400)
def verify_khalti_payment(pidx):
    url = "https://khalti.com/api/v2/payment/verify/"
    headers = {
        "Authorization": f"Key {settings.KHALTI_SECRET_KEY}"
    }
    data = {
        "pidx": pidx
    }

    response = requests.post(url, headers=headers, data=data)
    return response.json()

def payment_success_view(request):
    return render(request, 'payment_success.html')

@csrf_exempt
def stripe_create_payment_intent(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            amount = data.get('amount')  # Amount in cents
            currency = data.get('currency', 'usd')
            product_id = data.get('product_id')
            quantity = data.get('quantity')
            customer_details = data.get('customer_details', {})

            # Create payment intent
            intent = stripe.PaymentIntent.create(
                amount=amount,
                currency=currency,
                metadata={
                    'product_id': product_id,
                    'quantity': quantity,
                    'customer_name': customer_details.get('name', ''),
                    'customer_phone': customer_details.get('phone', ''),
                    'customer_city': customer_details.get('city', ''),
                    'customer_address': customer_details.get('address', '')
                }
            )

            return JsonResponse({
                'client_secret': intent.client_secret,
                'payment_intent_id': intent.id
            })

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def stripe_confirm_payment(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            payment_intent_id = data.get('payment_intent_id')

            # Retrieve payment intent to confirm it's successful
            intent = stripe.PaymentIntent.retrieve(payment_intent_id)

            if intent.status == 'succeeded':
                return JsonResponse({
                    'status': 'success',
                    'message': 'Payment confirmed successfully'
                })
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Payment not successful'
                }, status=400)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=405)

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from .models import Product, ProductReview
import json

@csrf_exempt
def submit_review(request):
    if request.method == 'POST':
        data = json.loads(request.body)

        rating = data.get('rating')
        product_id = data.get('product_id')

        if not request.user.is_authenticated:
            return JsonResponse({'status': 'error', 'message': 'User not authenticated'})

        try:
            product = Product.objects.get(id=product_id)
            # Prevent duplicate review per user-product
            existing_review = ProductReview.objects.filter(user=request.user, product=product).first()
            if existing_review:
                existing_review.rating = rating
                existing_review.save()
            else:
                ProductReview.objects.create(
                    user=request.user,
                    product=product,
                    rating=rating
                )

            # Optionally, update product rating average
            all_reviews = ProductReview.objects.filter(product=product)
            avg_rating = sum(r.rating for r in all_reviews) / all_reviews.count()
            product.rating = round(avg_rating, 1)
            product.reviews = all_reviews.count()
            product.save()

            return JsonResponse({'status': 'success'})

        except Product.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Product not found'})

    return JsonResponse({'status': 'error', 'message': 'Invalid request'})

def search_view(request):
    search_query = request.GET.get('q', '').strip()
    category_name = request.GET.get('type', '').strip()

    categories = Category.objects.all().order_by('name')
    products = Product.objects.all()

    if category_name and category_name.lower() != "all":
        products = products.filter(category__name__iexact=category_name)

    if search_query:
        products = products.filter(
            Q(name__icontains=search_query) |
            Q(description__icontains=search_query)
        )

    for product in products:
        try:
            product.color_options = json.loads(product.color_options or "[]")
        except:
            product.color_options = []

    return render(request, 'search.html', {
        'products': products,
        'categories': categories,
        'search_query': search_query,
        'selected_category': category_name,
    })

@csrf_exempt
def check_password_strength(request):
    """API endpoint for real-time password strength checking"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            password = data.get('password', '')
            
            is_valid, errors, strength_score = PasswordValidator.validate_password_strength(password)
            strength_label = PasswordValidator.get_strength_label(strength_score)
            
            return JsonResponse({
                'is_valid': is_valid,
                'errors': errors,
                'strength_score': strength_score,
                'strength_label': strength_label,
                'max_score': 10
            })
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    return JsonResponse({'error': 'Method not allowed'}, status=405)

@csrf_exempt
def check_password_reuse(request):
    """API endpoint to check if password was used recently"""
    if request.method == 'POST' and request.user.is_authenticated:
        try:
            data = json.loads(request.body)
            password = data.get('password', '')
            
            can_use, message = PasswordValidator.check_password_reuse(request.user, password)
            
            return JsonResponse({
                'can_use': can_use,
                'message': message
            })
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)
    
    return JsonResponse({'error': 'Unauthorized'}, status=401)

@login_required
def change_password_view(request):
    """Password change view with enhanced security"""
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        # Verify current password
        if not request.user.check_password(current_password):
            messages.error(request, "Current password is incorrect.")
            return redirect('change_password')
        
        # Check if new passwords match
        if new_password != confirm_password:
            messages.error(request, "New passwords do not match.")
            return redirect('change_password')
        
        # Validate password strength
        is_valid, errors, strength_score = PasswordValidator.validate_password_strength(new_password)
        if not is_valid:
            for error in errors:
                messages.error(request, error)
            return redirect('change_password')
        
        # Check password reuse
        can_use, reuse_message = PasswordValidator.check_password_reuse(request.user, new_password)
        if not can_use:
            messages.error(request, reuse_message)
            return redirect('change_password')
        
        # Update password
        request.user.set_password(new_password)
        request.user.save()
        
        # Save to password history
        PasswordValidator.save_password_history(request.user, new_password)
        
        # Update security settings
        security_settings, created = UserSecuritySettings.objects.get_or_create(user=request.user)
        security_settings.password_last_changed = timezone.now()
        security_settings.force_password_change = False
        security_settings.save()
        
        # Log activity
        SecurityUtils.log_activity(
            request.user, 'PASSWORD_CHANGE', 
            'Password changed successfully',
            request, True
        )
        
        # Update session to prevent logout
        update_session_auth_hash(request, request.user)
        
        messages.success(request, "Password changed successfully.")
        return redirect('account')
    
    # Check if password change is forced
    force_change = request.session.get('force_password_change')
    if force_change:
        messages.warning(request, "You must change your password to continue.")
    
    return render(request, 'change_password.html', {
        'force_change': force_change
    })

@login_required
def security_dashboard_view(request):
    """Security dashboard showing user's security status"""
    try:
        security_settings = request.user.security_settings
    except UserSecuritySettings.DoesNotExist:
        security_settings = UserSecuritySettings.objects.create(user=request.user)
    
    # Get recent activity logs
    recent_activities = ActivityLog.objects.filter(user=request.user)[:10]
    
    # Check password expiry
    password_expired = PasswordValidator.is_password_expired(request.user)
    days_until_expiry = None
    if not password_expired:
        expiry_date = security_settings.password_last_changed + timedelta(
            days=PasswordValidator.PASSWORD_EXPIRY_DAYS
        )
        days_until_expiry = (expiry_date - timezone.now()).days
    
    context = {
        'security_settings': security_settings,
        'recent_activities': recent_activities,
        'password_expired': password_expired,
        'days_until_expiry': days_until_expiry,
        'mfa_enabled': security_settings.mfa_enabled,
    }
    
    return render(request, 'security_dashboard.html', context)

@admin_required
def test_encryption_view(request):
    """Test encryption functionality - Admin only"""
    if request.method == 'POST':
        # Test basic encryption/decryption
        test_results = EncryptionValidator.test_encryption()
        
        # Test model encryption with sample data
        from .models import UserProfile, ContactMessage, Payment, UserSecuritySettings
        
        # Create test instances (don't save to DB)
        test_profile = UserProfile(phone="1234567890")
        test_profile._encrypt_fields()
        
        test_contact = ContactMessage(
            name="John Doe",
            email="john@example.com", 
            phone="9876543210"
        )
        test_contact._encrypt_fields()
        
        model_tests = {
            'UserProfile': EncryptionValidator.validate_model_encryption(test_profile, ['phone']),
            'ContactMessage': EncryptionValidator.validate_model_encryption(test_contact, ['name', 'email', 'phone'])
        }
        
        context = {
            'test_results': test_results,
            'model_tests': model_tests,
            'encryption_working': all(result.get('success', False) for result in test_results)
        }
        
        return JsonResponse(context)
    
    return render(request, 'test_encryption.html')

@admin_required
def encryption_status_view(request):
    """View encryption status of existing data - Admin only"""
    from .models import UserProfile, ContactMessage, Payment, UserSecuritySettings, ActivityLog
    
    # Check encryption status of existing records
    encryption_status = {}
    
    # UserProfile encryption status
    profiles_with_encryption = UserProfile.objects.exclude(_phone_encrypted__isnull=True).exclude(_phone_encrypted='')
    encryption_status['UserProfile'] = {
        'total_records': UserProfile.objects.count(),
        'encrypted_records': profiles_with_encryption.count(),
        'encryption_percentage': (profiles_with_encryption.count() / max(UserProfile.objects.count(), 1)) * 100
    }
    
    # ContactMessage encryption status
    contacts_with_encryption = ContactMessage.objects.exclude(_email_encrypted__isnull=True).exclude(_email_encrypted='')
    encryption_status['ContactMessage'] = {
        'total_records': ContactMessage.objects.count(),
        'encrypted_records': contacts_with_encryption.count(),
        'encryption_percentage': (contacts_with_encryption.count() / max(ContactMessage.objects.count(), 1)) * 100
    }
    
    # Payment encryption status
    payments_with_encryption = Payment.objects.exclude(_khalti_token_encrypted__isnull=True).exclude(_khalti_token_encrypted='')
    encryption_status['Payment'] = {
        'total_records': Payment.objects.count(),
        'encrypted_records': payments_with_encryption.count(),
        'encryption_percentage': (payments_with_encryption.count() / max(Payment.objects.count(), 1)) * 100
    }
    
    context = {
        'encryption_status': encryption_status,
        'overall_encryption_health': sum(status['encryption_percentage'] for status in encryption_status.values()) / len(encryption_status)
    }
    
    return render(request, 'encryption_status.html', context)

@admin_required  
def encrypt_existing_data_view(request):
    """Encrypt existing unencrypted data - Admin only"""
    if request.method == 'POST':
        from .models import UserProfile, ContactMessage, Payment, UserSecuritySettings, ActivityLog
        
        results = {
            'encrypted_records': 0,
            'errors': [],
            'details': {}
        }
        
        try:
            # Encrypt UserProfile records
            profiles_to_encrypt = UserProfile.objects.filter(
                models.Q(_phone_encrypted__isnull=True) | models.Q(_phone_encrypted=''),
                phone__isnull=False
            ).exclude(phone='')
            
            profile_count = 0
            for profile in profiles_to_encrypt:
                try:
                    profile.save()  # This will trigger encryption
                    profile_count += 1
                except Exception as e:
                    results['errors'].append(f"UserProfile {profile.id}: {str(e)}")
            
            results['details']['UserProfile'] = profile_count
            results['encrypted_records'] += profile_count
            
            # Encrypt ContactMessage records
            contacts_to_encrypt = ContactMessage.objects.filter(
                models.Q(_email_encrypted__isnull=True) | models.Q(_email_encrypted=''),
                email__isnull=False
            ).exclude(email='')
            
            contact_count = 0
            for contact in contacts_to_encrypt:
                try:
                    contact.save()  # This will trigger encryption
                    contact_count += 1
                except Exception as e:
                    results['errors'].append(f"ContactMessage {contact.id}: {str(e)}")
            
            results['details']['ContactMessage'] = contact_count
            results['encrypted_records'] += contact_count
            
            # Encrypt Payment records
            payments_to_encrypt = Payment.objects.filter(
                models.Q(_khalti_token_encrypted__isnull=True) | models.Q(_khalti_token_encrypted=''),
                khalti_token__isnull=False
            ).exclude(khalti_token='')
            
            payment_count = 0
            for payment in payments_to_encrypt:
                try:
                    payment.save()  # This will trigger encryption
                    payment_count += 1
                except Exception as e:
                    results['errors'].append(f"Payment {payment.id}: {str(e)}")
            
            results['details']['Payment'] = payment_count
            results['encrypted_records'] += payment_count
            
        except Exception as e:
            results['errors'].append(f"General error: {str(e)}")
        
        return JsonResponse(results)
    
    return render(request, 'encrypt_existing_data.html')

@csrf_exempt
def generate_captcha_view(request):
    """Generate a new CAPTCHA for the login form"""
    try:
        captcha_data = CaptchaGenerator.generate_captcha()
        return JsonResponse({
            'success': True,
            'captcha_key': captcha_data['key'],
            'captcha_image': captcha_data['image_url']
        })
    except Exception as e:
        # Fallback to math CAPTCHA
        try:
            math_captcha = SimpleCaptcha.generate_math_captcha()
            return JsonResponse({
                'success': True,
                'captcha_key': math_captcha['key'],
                'captcha_question': math_captcha['question'],
                'captcha_type': 'math'
            })
        except Exception as e2:
            return JsonResponse({
                'success': False,
                'error': 'Failed to generate CAPTCHA'
            })
