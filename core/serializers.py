from rest_framework import serializers
from .models import User, Membership, Payment, TransactionLedger, Voucher, UserVoucher, AdminActivityLog
import base64
import uuid
from django.core.files.base import ContentFile
import cloudinary.uploader
import logging

logger = logging.getLogger(__name__)

class Base64ImageField(serializers.ImageField):
    def to_internal_value(self, data):
        if isinstance(data, str) and data.startswith('data:image'):
            try:
                format, imgstr = data.split(';base64,')
                ext = format.split('/')[-1]
                data = ContentFile(base64.b64decode(imgstr), name=f"{uuid.uuid4()}.{ext}")
            except Exception:
                raise serializers.ValidationError("Invalid image format")
        return super().to_internal_value(data)


class UserSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='full_name')
    mobile = serializers.CharField(source='phone')
    profile_picture = serializers.SerializerMethodField()
    profile_pic = serializers.URLField(read_only=True)
    profile_pic_public_id = serializers.CharField(read_only=True)
    membership_status = serializers.SerializerMethodField()
    last_payment_date = serializers.SerializerMethodField()
    membership_end_date = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'name', 'email', 'mobile', 'profile_picture', 'profile_pic', 'profile_pic_public_id', 'role', 'status', 'created_at', 'membership_status', 'last_payment_date', 'membership_end_date')
        read_only_fields = ('id', 'email', 'role', 'status', 'created_at')

    def get_profile_picture(self, obj):
        if obj.profile_pic:
            return obj.profile_pic
        if obj.profile_image:
            return obj.profile_image.url
        return None

    def get_membership_status(self, obj):
        membership = obj.memberships.filter(status='ACTIVE').order_by('-end_date').first()
        return membership.effective_status if membership else 'NONE'

    def get_last_payment_date(self, obj):
        last_payment = obj.payments.filter(payment_status='SUCCESS').order_by('-paid_at').first()
        return last_payment.paid_at.isoformat() if last_payment and last_payment.paid_at else None
    # this is for admin to get the membership end date
    def get_membership_end_date(self, obj):
        membership = obj.memberships.filter(status='ACTIVE').order_by('-end_date').first()
        if not membership:
            # Fallback to expired if no active exists
            membership = obj.memberships.all().order_by('-end_date').first()
        return membership.end_date.isoformat() if membership else None


class RegisterSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='full_name')
    phone = serializers.CharField()
    profilePicture = Base64ImageField(source='profile_image', required=False)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('name', 'email', 'phone', 'password', 'profilePicture')

    def create(self, validated_data):
        profile_image = validated_data.pop('profile_image', None)
        
        user = User.objects.create_user(
            email=validated_data['email'],
            phone=validated_data['phone'],
            full_name=validated_data['full_name'],
            password=validated_data['password']
        )
        
        if profile_image:
            try:
                # Upload to Cloudinary
                upload_result = cloudinary.uploader.upload(
                    profile_image,
                    folder=f"club369/profile_pics/{user.id}",
                    transformation="c_fill,w_200,h_200,q_auto:good"
                )
                user.profile_pic = upload_result.get('secure_url')
                user.profile_pic_public_id = upload_result.get('public_id')
                user.save()
            except Exception as e:
                logger.error(f"Failed to upload profile picture to Cloudinary: {str(e)}")
                # Continue without image rather than breaking registration
        
        return user



class MembershipSerializer(serializers.ModelSerializer):
    class Meta:
        model = Membership
        fields = '__all__'

class MembershipDetailSerializer(serializers.ModelSerializer):
    expiryDate = serializers.DateField(source='end_date')
    nextBillingDate = serializers.DateField(source='end_date') # Simplified for now
    autopayStatus = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()

    class Meta:
        model = Membership
        fields = ('status', 'expiryDate', 'nextBillingDate', 'autopayStatus')

    def get_autopayStatus(self, obj):
        return 'active' if obj.auto_pay_enabled else 'inactive'

    def get_status(self, obj):
        return obj.effective_status.upper()

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'

class TransactionLedgerSerializer(serializers.ModelSerializer):
    date = serializers.DateTimeField(source='transaction_date')
    method = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()
    user_name = serializers.CharField(source='user.full_name', read_only=True)
    

    class Meta:
        model = TransactionLedger
        fields = ('id', 'user', 'user_name', 'date', 'amount', 'status', 'method')

    def get_method(self, obj):
        return obj.payment.payment_mode if obj.payment else 'Unknown'

    def get_status(self, obj):
        return 'success' if obj.payment and obj.payment.payment_status == 'SUCCESS' else 'failed'

class VoucherSerializer(serializers.ModelSerializer):
    title = serializers.CharField(source='voucher_name')
    isClaimed = serializers.SerializerMethodField()
    code = serializers.SerializerMethodField()

    class Meta:
        model = Voucher
        fields = ('id', 'title', 'description', 'isClaimed', 'code')

    def get_isClaimed(self, obj):
        user = self.context.get('request').user if 'request' in self.context else None
        if user and user.is_authenticated:
            return UserVoucher.objects.filter(user=user, voucher=obj).exists()
        return False

    def get_code(self, obj):
        user = self.context.get('request').user if 'request' in self.context else None
        if user and user.is_authenticated:
            if UserVoucher.objects.filter(user=user, voucher=obj).exists():
                return obj.voucher_code
        return "********"

class UserVoucherSerializer(serializers.ModelSerializer):
    voucher_details = VoucherSerializer(source='voucher', read_only=True)
    class Meta:
        model = UserVoucher
        fields = ('id', 'user', 'voucher', 'voucher_details', 'status', 'claimed_at', 'used_at')

class AdminActivityLogSerializer(serializers.ModelSerializer):
    admin_name = serializers.CharField(source='admin.full_name', read_only=True)
    class Meta:
        model = AdminActivityLog
        fields = '__all__'


class AdminVoucherSerializer(serializers.ModelSerializer):
    title = serializers.CharField(source='voucher_name')
    usageCount = serializers.SerializerMethodField()
    usedBy = serializers.SerializerMethodField()
    expiryDate = serializers.DateTimeField(source='valid_until')
    code = serializers.CharField(source='voucher_code')
    isSuspended = serializers.SerializerMethodField()

    class Meta:
        model = Voucher
        fields = ('id', 'title', 'code', 'description', 'max_usage_per_user', 'valid_from', 'expiryDate', 'isSuspended', 'usageCount', 'usedBy')

    def get_usageCount(self, obj):
        return obj.user_vouchers.count()

    def get_usedBy(self, obj):
        return [uv.user.full_name for uv in obj.user_vouchers.all()]

    def get_isSuspended(self, obj):
        return not obj.is_active

