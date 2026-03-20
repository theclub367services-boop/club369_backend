from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone
from django.db.models.signals import post_delete
from django.dispatch import receiver
import cloudinary.uploader
import os

class UserManager(BaseUserManager):
    def create_user(self, email, phone, full_name, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        if not phone:
            raise ValueError('Users must have a phone number')
        
        email = self.normalize_email(email)
        user = self.model(email=email, phone=phone, full_name=full_name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, phone, full_name, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'ADMIN')
        extra_fields.setdefault('status', 'ACTIVE')
        
        return self.create_user(email, phone, full_name, password, **extra_fields)

class User(AbstractBaseUser, PermissionsMixin):
    ROLE_CHOICES = (
        ('USER', 'User'),
        ('ADMIN', 'Admin'),
    )
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('ACTIVE', 'Active'),
        ('SUSPENDED', 'Suspended'),
    )

    full_name = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20, unique=True)
    profile_image = models.ImageField(upload_to='profiles/', null=True, blank=True)
    profile_pic = models.URLField(max_length=500, blank=True, null=True)
    profile_pic_public_id = models.CharField(max_length=255, blank=True, null=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='USER')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'phone']

    def __str__(self):
        return self.email

class Membership(models.Model):
    STATUS_CHOICES = (
        ('ACTIVE', 'Active'),
        ('EXPIRED', 'Expired'),
        ('INACTIVE', 'Inactive'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='memberships')
    plan_name = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    start_date = models.DateField()
    end_date = models.DateField()
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='ACTIVE')
    auto_pay_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def effective_status(self):
        if self.status == 'ACTIVE' and self.end_date < timezone.now().date():
            return 'EXPIRED' 
            # It doesnt update the status to expired in the database,actually most efficient way,update the database status, but architecturally, it is not a good idea,silently trigger UPDATE SQL queries in the background. Your API endpoint will suddenly become very slow.
        return self.status

    def __str__(self):
        return f"{self.user.email} - {self.plan_name} ({self.effective_status})"

class Payment(models.Model):
    PAYMENT_MODE_CHOICES = (
        ('UPI', 'UPI'),
        ('CARD', 'Card'),
        ('NETBANKING', 'Netbanking'),
        ('MANUAL', 'Manual'),
    )
    PAYMENT_STATUS_CHOICES = (
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
        ('PENDING', 'Pending'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments')
    membership = models.ForeignKey(Membership, on_delete=models.CASCADE, related_name='payments')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    payment_mode = models.CharField(max_length=20, choices=PAYMENT_MODE_CHOICES)
    transaction_id = models.CharField(max_length=255, unique=True)
    payment_status = models.CharField(max_length=10, choices=PAYMENT_STATUS_CHOICES, default='PENDING')
    paid_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

class TransactionLedger(models.Model):
    TRANSACTION_TYPE_CHOICES = (
        ('CREDIT', 'Credit'),
    )
    payment = models.ForeignKey(Payment, on_delete=models.CASCADE, related_name='ledger_entries')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ledger_entries')
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_type = models.CharField(max_length=10, choices=TRANSACTION_TYPE_CHOICES, default='CREDIT')
    description = models.TextField()
    transaction_date = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)

class Venture(models.Model):
    TYPE_CHOICES = (
        ('OWN', 'Own'),
        ('PARTNER', 'Partner'),
    )
    STATUS_CHOICES = (
        ('ACTIVE', 'Active'),
        ('SUSPENDED', 'Suspended'),
    )
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=10, choices=TYPE_CHOICES, default='OWN')
    discount_percentage = models.DecimalField(max_digits=5, decimal_places=2)
    poster = models.ImageField(upload_to='ventures/posters/', max_length=500, null=True, blank=True)
    poster_public_id = models.CharField(max_length=255, null=True, blank=True)
    icon = models.ImageField(upload_to='ventures/icons/', max_length=500, null=True, blank=True)
    icon_public_id = models.CharField(max_length=255, null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='ACTIVE')
    is_deleted = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class Branch(models.Model):
    venture = models.ForeignKey(Venture, on_delete=models.CASCADE, related_name='branches')
    branch_name = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.venture.name} - {self.branch_name}"

class Redemption(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='redemptions')
    venture = models.ForeignKey(Venture, on_delete=models.CASCADE, related_name='redemptions')
    branch = models.ForeignKey(Branch, on_delete=models.CASCADE, related_name='redemptions')
    actual_bill_amount = models.DecimalField(max_digits=10, decimal_places=2)
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2)
    final_paid_amount = models.DecimalField(max_digits=10, decimal_places=2)
    redeemed_at = models.DateField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.venture.name} - {self.final_paid_amount}"


import uuid

class UserSession(models.Model):
    id = models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='active_sessions')
    session_key = models.UUIDField(default=uuid.uuid4, editable=False, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def __str__(self):
        return f"{self.user.email} - {self.session_key}"

class PaymentOrder(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    razorpay_order_id = models.CharField(max_length=255, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10, default="INR")
    status = models.CharField(max_length=50, default="CREATED")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.razorpay_order_id} - {self.status}"

class AutoPaySubscription(models.Model):
    STATUS_CHOICES = (
        ('ENABLED', 'Enabled'),
        ('CANCELLED', 'Cancelled'),
    )
    CYCLE_STATUS_CHOICES = (
        ('PAID', 'Paid'),
        ('UNPAID', 'Unpaid'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='autopay_subscriptions')
    razorpay_subscription_id = models.CharField(max_length=255, unique=True, db_index=True)
    autopay_status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='ENABLED')
    current_cycle_status = models.CharField(max_length=15, choices=CYCLE_STATUS_CHOICES, default='UNPAID')
    last_payment_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.email} - {self.razorpay_subscription_id} - {self.autopay_status}"

@receiver(post_delete, sender=User)
def delete_user_cloudinary_assets(sender, instance, **kwargs):
    """
    Ensures that when a User is deleted, their profile picture 
    is also removed from Cloudinary to save storage space.
    """
    if instance.profile_pic_public_id:
        try:
            cloudinary.uploader.destroy(instance.profile_pic_public_id)
        except Exception as e:
            # Log error but don't block deletion
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to delete Cloudinary asset for user {instance.id}: {str(e)}")
