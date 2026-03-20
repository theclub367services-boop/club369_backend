from rest_framework import serializers
from .models import User, Membership, Payment, TransactionLedger, Venture, Branch, Redemption
import base64
import uuid
from django.core.files.base import ContentFile
import cloudinary.uploader
import logging
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)

class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token['email'] = getattr(user, 'email', '')
        token['role'] = getattr(user, 'role', 'USER')
        # session_key is injected from the view after creation
        return token

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
    autopay_status = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ('id', 'name', 'email', 'mobile', 'profile_picture', 'profile_pic', 'profile_pic_public_id', 'role', 'status', 'created_at', 'membership_status', 'last_payment_date', 'membership_end_date', 'autopay_status')
        read_only_fields = ('id', 'email', 'role', 'status', 'created_at')

    def get_profile_picture(self, obj):
        if obj.profile_pic:
            return obj.profile_pic
        if obj.profile_image:
            return obj.profile_image.url
        return None

    def get_membership_status(self, obj):
        membership = obj.memberships.filter(status='ACTIVE').order_by('-end_date').first()
        is_membership_active = membership and membership.effective_status == 'ACTIVE'

        autopay = getattr(obj, 'autopay_subscriptions', None)
        active_autopay = autopay.filter(autopay_status='ENABLED', current_cycle_status='PAID').exists() if autopay else False

        if is_membership_active or active_autopay:
            return 'ACTIVE'
            
        return membership.effective_status if membership else 'INACTIVE'

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

    def get_autopay_status(self, obj):
        autopay = getattr(obj, 'autopay_subscriptions', None)
        if autopay:
            sub = autopay.filter(autopay_status='ENABLED').first()
            if sub:
                return 'ENABLED'
            cancelled = autopay.filter(autopay_status='CANCELLED').first()
            if cancelled:
                return 'CANCELLED'
            return 'DISABLED'
        return 'DISABLED'


class RegisterSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source='full_name')
    phone = serializers.CharField()
    profilePicture = Base64ImageField(source='profile_image', required=False, allow_null=True)
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
    startDate = serializers.DateField(source='start_date')
    autopayStatus = serializers.SerializerMethodField()
    status = serializers.SerializerMethodField()

    class Meta:
        model = Membership
        fields = ('status', 'startDate', 'expiryDate', 'nextBillingDate', 'autopayStatus')

    def get_autopayStatus(self, obj):
        autopay = getattr(obj.user, 'autopay_subscriptions', None)
        if autopay and autopay.filter(autopay_status='ENABLED').exists():
            return 'active'
        return 'inactive'

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
    transaction_id = serializers.CharField(source='payment.transaction_id', read_only=True)

    class Meta:
        model = TransactionLedger
        fields = ('id', 'user', 'user_name', 'date', 'amount', 'status', 'method','transaction_id')

    def get_method(self, obj):
        return obj.payment.payment_mode if obj.payment else 'Unknown'

    def get_status(self, obj):
        return 'success' if obj.payment and obj.payment.payment_status == 'SUCCESS' else 'failed'

class BranchSerializer(serializers.ModelSerializer):
    class Meta:
        model = Branch
        fields = ('id', 'venture', 'branch_name')

class VentureSerializer(serializers.ModelSerializer):
    branches = BranchSerializer(many=True, read_only=True)
    class Meta:
        model = Venture
        fields = ('id', 'name', 'type', 'discount_percentage', 'poster', 'icon', 'status', 'branches')

class RedemptionSerializer(serializers.ModelSerializer):
    venture_name = serializers.CharField(source='venture.name', read_only=True)
    branch_name = serializers.CharField(source='branch.branch_name', read_only=True)
    user_name = serializers.CharField(source='user.full_name', read_only=True)

    class Meta:
        model = Redemption
        fields = ('id', 'user', 'user_name', 'venture', 'venture_name', 'branch', 'branch_name', 
                  'actual_bill_amount', 'discount_amount', 'final_paid_amount', 'redeemed_at')

class AdminVentureSerializer(serializers.ModelSerializer):
    branches = serializers.SerializerMethodField()
    branch_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Venture
        fields = ('id', 'name', 'type', 'discount_percentage', 'poster', 'poster_public_id', 'icon', 'icon_public_id', 'status', 'is_deleted', 'branches', 'branch_count')

    def get_branches(self, obj):
        return BranchSerializer(obj.branches.all(), many=True).data

    def get_branch_count(self, obj):
        return obj.branches.count()

