from django.shortcuts import get_object_or_404, render,redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login
from .models import Category, Product  # Import Product model
import json
from .models import UserProfile  # Add this at the top
from django.contrib.auth.hashers import make_password

from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash

from django.contrib.auth.models import User   # <--- Add this line
from django.shortcuts import render, redirect
from django.core.mail import send_mail
import random
from django.conf import settings
from .models import Payment  # Make sure you have this model
from django.views.decorators.csrf import csrf_exempt

from django.db.models import Q

# Import security utilities
from .security_utils import PasswordValidator, SecurityUtils, RateLimiter
from .models import UserSecuritySettings, UserRole
from django.utils import timezone
from django.http import JsonResponse

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
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Rate limiting check
        client_ip = SecurityUtils.get_client_ip(request)
        if RateLimiter.is_rate_limited(f"login_{client_ip}", max_requests=10, window_minutes=15):
            messages.error(request, "Too many login attempts. Please try again later.")
            return redirect('login')

        # Check if user exists
        try:
            user = User.objects.get(username=email)
        except User.DoesNotExist:
            # Log failed attempt for non-existent user
            SecurityUtils.log_activity(
                None, 'LOGIN_FAILED', 
                f'Login attempt for non-existent user: {email}',
                request, False
            )
            messages.error(request, "Invalid email or password.")
            return redirect('login')

        # Check if account is locked
        if SecurityUtils.is_account_locked(user):
            remaining_minutes = SecurityUtils.get_lockout_remaining_time(user)
            if remaining_minutes > 0:
                messages.error(request, f"Account is locked due to multiple failed login attempts. Please try again in {remaining_minutes} minute(s).")
            else:
                messages.error(request, "Account is locked due to multiple failed login attempts. Please try again later.")
            return redirect('login')

        # Check password expiry
        if PasswordValidator.is_password_expired(user):
            messages.warning(request, "Your password has expired. Please change your password.")
            request.session['force_password_change'] = user.id
            return redirect('change_password')

        # Authenticate user
        authenticated_user = authenticate(request, username=email, password=password)

        if authenticated_user is not None:
            # Handle successful login
            SecurityUtils.handle_successful_login(user, request)
            login(request, authenticated_user)
            messages.success(request, "Logged in successfully.")
            
            # Check if MFA is enabled
            try:
                if user.security_settings.mfa_enabled:
                    request.session['pending_mfa_user'] = user.id
                    return redirect('mfa_verify')
            except UserSecuritySettings.DoesNotExist:
                pass
            
            return render(request, 'login.html', {'redirect_after_login': True})
        else:
            # Handle failed login
            SecurityUtils.handle_failed_login(user, request)
            
            # Get updated security settings to show remaining attempts
            security_settings = user.security_settings
            remaining_attempts = SecurityUtils.MAX_LOGIN_ATTEMPTS - security_settings.failed_login_attempts
            
            if remaining_attempts > 0:
                messages.error(request, f"Invalid email or password. {remaining_attempts} attempts remaining.")
            else:
                messages.error(request, "Account has been locked due to multiple failed login attempts.")
            
            return redirect('login')

    return render(request, 'login.html')
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
        subject = 'FurniFlex Password Reset OTP'
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

    context = {
        'name': user.first_name,
        'email': user.email,
        'phone': phone
    }
    return render(request, 'account.html', context)
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
#             ['furniflex@gmail.com'],  # To email (or a list of recipients)
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
                    subject = 'Your FurniFlex Order is Confirmed - Stripe Payment'
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

We will process and deliver your order soon. Thank you for shopping with FurniFlex!

Best regards,
FurniFlex Team
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

        subject = 'Your FurniFlex Order is Confirmed (Cash on Delivery)'
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

We will deliver your order soon. Thank you for shopping with FurniFlex!

Best,
FurniFlex Team
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
            "purchase_order_name": "FurniFlex Order"
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
