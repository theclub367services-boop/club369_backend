from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone

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
    profile_pic = models.URLField(blank=True, null=True)
    profile_pic_public_id = models.CharField(max_length=255, blank=True, null=True)
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='USER')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='PENDING')
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'phone']

    def __str__(self):
        return self.email

class Membership(models.Model):
    STATUS_CHOICES = (
        ('ACTIVE', 'Active'),
        ('EXPIRED', 'Expired'),
        ('NONE', 'None'),
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
        return self.status

    def __str__(self):
        return f"{self.user.email} - {self.plan_name} ({self.effective_status})"

class Payment(models.Model):
    PAYMENT_MODE_CHOICES = (
        ('UPI', 'UPI'),
        ('CARD', 'Card'),
        ('NETBANKING', 'Netbanking'),
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

class Voucher(models.Model):
    voucher_code = models.CharField(max_length=50, unique=True)
    voucher_name = models.CharField(max_length=100)
    description = models.TextField()
    max_usage_per_user = models.PositiveIntegerField(default=1)
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField()
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

class UserVoucher(models.Model):
    STATUS_CHOICES = (
        ('CLAIMED', 'Claimed'),
        ('USED', 'Used'),
    )
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_vouchers')
    voucher = models.ForeignKey(Voucher, on_delete=models.CASCADE, related_name='user_vouchers')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='CLAIMED')
    claimed_at = models.DateTimeField(auto_now_add=True)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ('user', 'voucher')

class AdminActivityLog(models.Model):
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name='admin_logs')
    action = models.CharField(max_length=255)
    target_id = models.CharField(max_length=100, null=True, blank=True)
    remarks = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

class PaymentOrder(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    razorpay_order_id = models.CharField(max_length=255, unique=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10, default="INR")
    status = models.CharField(max_length=50, default="CREATED")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.razorpay_order_id} - {self.status}"
