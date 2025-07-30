from django.db import models
from django.contrib.auth.models import User
from .encryption_utils import DataEncryptionMixin, FieldEncryption

class Category(models.Model):
    name = models.CharField(max_length=100)

    def __str__(self):
        return self.name

class Product(models.Model):
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='products')
    name = models.CharField(max_length=100)
    description = models.TextField()
    price = models.DecimalField(max_digits=10, decimal_places=2)
    image = models.ImageField(upload_to='products/')
    thumbnail1 = models.ImageField(upload_to='products/', blank=True, null=True)
    thumbnail2 = models.ImageField(upload_to='products/', blank=True, null=True)
    thumbnail3 = models.ImageField(upload_to='products/', blank=True, null=True)
    thumbnail4 = models.ImageField(upload_to='products/', blank=True, null=True)
    thumbnail5 = models.ImageField(upload_to='products/', blank=True, null=True)
    color_options = models.JSONField(default=list)  # e.g. ["black", "gray"]
    reviews = models.PositiveIntegerField(default=0)
    rating = models.FloatField(default=0.0)

    def __str__(self):
        return self.name

class UserProfile(DataEncryptionMixin, models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    phone = models.CharField(max_length=20, blank=True, null=True)
    profile_image = models.ImageField(upload_to='profile_images/', default='profile_images/default.jpg')
    
    # Encrypted fields
    _phone_encrypted = models.TextField(blank=True, null=True)
    
    ENCRYPTED_FIELDS = ['phone']
    
    @property
    def phone_decrypted(self):
        """Get decrypted phone number"""
        return self.get_decrypted_field('phone')

class ContactMessage(DataEncryptionMixin, models.Model):
    name = models.CharField(max_length=100, blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    message = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)
    
    # Encrypted fields
    _name_encrypted = models.TextField(blank=True, null=True)
    _email_encrypted = models.TextField(blank=True, null=True)
    _phone_encrypted = models.TextField(blank=True, null=True)
    
    ENCRYPTED_FIELDS = ['name', 'email', 'phone']

    def __str__(self):
        return self.get_decrypted_field('name') or 'Anonymous'
    
    @property
    def name_decrypted(self):
        return self.get_decrypted_field('name')
    
    @property
    def email_decrypted(self):
        return self.get_decrypted_field('email')
    
    @property
    def phone_decrypted(self):
        return self.get_decrypted_field('phone')
    
class Payment(DataEncryptionMixin, models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE)
    full_name = models.CharField(max_length=255, blank=True, null=True)
    phone = models.CharField(max_length=20, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    khalti_token = models.CharField(max_length=100, blank=True, null=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Encrypted fields
    _full_name_encrypted = models.TextField(blank=True, null=True)
    _phone_encrypted = models.TextField(blank=True, null=True)
    _city_encrypted = models.TextField(blank=True, null=True)
    _address_encrypted = models.TextField(blank=True, null=True)
    _khalti_token_encrypted = models.TextField(blank=True, null=True)
    
    ENCRYPTED_FIELDS = ['full_name', 'phone', 'city', 'address', 'khalti_token']

    def __str__(self):
        username = self.user.username if self.user else 'Unknown'
        product_name = self.product.name if self.product else 'Unknown Product'
        return f"Payment by {username} for {product_name}"
    
    @property
    def full_name_decrypted(self):
        return self.get_decrypted_field('full_name')
    
    @property
    def phone_decrypted(self):
        return self.get_decrypted_field('phone')
    
    @property
    def city_decrypted(self):
        return self.get_decrypted_field('city')
    
    @property
    def address_decrypted(self):
        return self.get_decrypted_field('address')
    
    @property
    def khalti_token_decrypted(self):
        return self.get_decrypted_field('khalti_token')

class ProductReview(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='product_reviews')
    rating = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username} - {self.product.name} - {self.rating}⭐"

# Security Models
class PasswordHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_history')
    password_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']

class UserSecuritySettings(DataEncryptionMixin, models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='security_settings')
    password_last_changed = models.DateTimeField(auto_now_add=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=32, blank=True, null=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    force_password_change = models.BooleanField(default=False)
    
    # Encrypted fields
    _mfa_secret_encrypted = models.TextField(blank=True, null=True)
    _last_login_ip_encrypted = models.TextField(blank=True, null=True)
    
    ENCRYPTED_FIELDS = ['mfa_secret', 'last_login_ip']
    
    def is_account_locked(self):
        from django.utils import timezone
        if self.account_locked_until and self.account_locked_until > timezone.now():
            return True
        return False
    
    @property
    def mfa_secret_decrypted(self):
        return self.get_decrypted_field('mfa_secret')
    
    @property
    def last_login_ip_decrypted(self):
        return self.get_decrypted_field('last_login_ip')

class ActivityLog(DataEncryptionMixin, models.Model):
    ACTION_CHOICES = [
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('LOGIN_FAILED', 'Failed Login'),
        ('PASSWORD_CHANGE', 'Password Change'),
        ('PROFILE_UPDATE', 'Profile Update'),
        ('PURCHASE', 'Purchase'),
        ('REVIEW_SUBMIT', 'Review Submitted'),
        ('ACCOUNT_LOCKED', 'Account Locked'),
        ('ACCOUNT_UNLOCKED', 'Account Unlocked'),
        ('MFA_ENABLED', 'MFA Enabled'),
        ('MFA_DISABLED', 'MFA Disabled'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    success = models.BooleanField(default=True)
    
    # Encrypted fields
    _ip_address_encrypted = models.TextField(blank=True, null=True)
    _user_agent_encrypted = models.TextField(blank=True, null=True)
    
    ENCRYPTED_FIELDS = ['ip_address', 'user_agent']
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        username = self.user.username if self.user else 'Anonymous'
        return f"{username} - {self.action} - {self.timestamp}"
    
    @property
    def ip_address_decrypted(self):
        return self.get_decrypted_field('ip_address')
    
    @property
    def user_agent_decrypted(self):
        return self.get_decrypted_field('user_agent')

class UserRole(models.Model):
    ROLE_CHOICES = [
        ('CUSTOMER', 'Customer'),
        ('ADMIN', 'Administrator'),
        ('MODERATOR', 'Moderator'),
        ('STAFF', 'Staff'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='role')
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='CUSTOMER')
    permissions = models.JSONField(default=list)  # Store specific permissions
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.user.username} - {self.role}"
