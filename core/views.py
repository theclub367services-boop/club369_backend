from django.contrib.auth import login, logout
from django.contrib.auth.hashers import check_password
from rest_framework import status, generics, permissions, views
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.utils import timezone
from django.utils import timezone
from datetime import timedelta
from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, Membership, Payment, TransactionLedger, PaymentOrder, AutoPaySubscription, UserSession, Venture, Branch, Redemption
from .serializers import (UserSerializer, RegisterSerializer, MembershipSerializer, PaymentSerializer, TransactionLedgerSerializer, MembershipDetailSerializer, CustomTokenObtainPairSerializer, VentureSerializer, BranchSerializer, RedemptionSerializer, AdminVentureSerializer)
from django.conf import settings
import os
import razorpay
import json
import time
import cloudinary.utils
import cloudinary.uploader
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.tokens import default_token_generator
import logging

logger = logging.getLogger(__name__)
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
import calendar

def add_one_month(source_date):
    """Adds exactly one calendar month to a date (or datetime), capping the day if necessary."""
    month = source_date.month
    year = source_date.year
    day = source_date.day
    
    if month == 12:
        month = 1
        year += 1
    else:
        month += 1
        
    last_day_of_month = calendar.monthrange(year, month)[1]
    day = min(day, last_day_of_month)
    
    return source_date.replace(year=year, month=month, day=day)

# --- Authentication ---


class LoginView(TokenObtainPairView):
    """
    Detailed Login Phase:
    1. Validates credentials.
    2. establishes Django session via login().
    3. Generates JWT tokens.
    4. Bridges tokens via request.session['jwt_tokens'].
    5. Returns non-sensitive user metadata.
    """
    def post(self, request, *args, **kwargs):
        # 1. Validation (Internal to TokenObtainPairView serializer)
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        
        user = serializer.user

        # 2. Lightweight User Session Creation (Absolute Timeout Tracking)
        timeout_hours = getattr(settings, 'ABSOLUTE_SESSION_TIMEOUT_HOURS', 24)
        expires_at = timezone.now() + timedelta(hours=timeout_hours) # 24h absolute timeout
        session = UserSession.objects.create(user=user, expires_at=expires_at)

        # 3. Token Generation
        # Inject the session_key into the token claims so we don't need DB lookups on normal requests
        refresh = CustomTokenObtainPairSerializer.get_token(user)
        refresh['session_key'] = str(session.session_key)

        # 4. Session Bridging
        request.session['jwt_tokens'] = {
            'access': str(refresh.access_token),
            'refresh': str(refresh)
        }

        # 5. View Response (Metadata only)
        user_data = UserSerializer(user).data
        return Response(user_data, status=status.HTTP_200_OK)

class CustomTokenRefreshView(TokenRefreshView):
    """
    Token Refresh Phase:
    1. Reads refresh_token from cookies.
    2. Validates and rotates tokens.
    3. Bridges tokens via session.
    """
    def post(self, request, *args, **kwargs):
        # 1. Token Discovery
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        
        if not refresh_token:
            return Response({"error": "Refresh token missing"}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Absolute Session Validation (Every 15 minutes when refresh happens)
        try:
            token_obj = RefreshToken(refresh_token)
            session_key = token_obj.get('session_key')
            
            if not session_key:
                return Response({"error": "Invalid session token"}, status=status.HTTP_401_UNAUTHORIZED)
            
            # Look up the session in the DB
            session = UserSession.objects.get(session_key=session_key)
            
            if timezone.now() > session.expires_at:
                # Session expired, force hard delete
                session.delete()
                return Response({"error": "Session expired"}, status=status.HTTP_401_UNAUTHORIZED)
                
        except (UserSession.DoesNotExist, Exception) as e:
            return Response({"error": "Invalid or expired session"}, status=status.HTTP_401_UNAUTHORIZED)

        # Inject into request data for parent view
        request.data['refresh'] = refresh_token
        
        # 2 & 3. Validation and Rotation (via parent view)
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Preserve session_key inside the new tokens
            new_refresh = RefreshToken(response.data.get('refresh'))
            new_refresh['session_key'] = session_key
            
            new_access = new_refresh.access_token

            # 4. Session Re-Bridging
            request.session['jwt_tokens'] = {
                'access': str(new_access),
                'refresh': str(new_refresh)
            }
            # 5. Success Response
            return Response({"message": "Tokens refreshed successfully"}, status=status.HTTP_200_OK)
        
        return response

class LogoutView(views.APIView):
    """
    Logout Phase:
    1. Destroys Django session.
    2. Instructs browser to delete cookies.
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request):
        # 1. Session Invalidation (Hard Delete via Token Claim)
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
        if refresh_token:
            try:
                token_obj = RefreshToken(refresh_token)
                session_key = token_obj.get('session_key')
                UserSession.objects.filter(session_key=session_key).delete()
            except Exception:
                pass # If token is invalid or missing session_key, gracefully proceed to delete cookies

        logout(request)

        # 2. Cookie Deletion
        response = Response({'status': 'Logged out successfully'}, status=status.HTTP_200_OK)
        
        cookie_settings = {
            'path': settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'),
            'domain': settings.SIMPLE_JWT.get('AUTH_COOKIE_DOMAIN'),
            'samesite': settings.SIMPLE_JWT.get('AUTH_COOKIE_SAMESITE'),
        }

        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'], **cookie_settings)
        response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'], **cookie_settings)
        
        return response

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.AllowAny,)
    serializer_class = RegisterSerializer

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        phone = request.data.get('phone')

        email_exists = User.objects.filter(email=email).exists() if email else False
        phone_exists = User.objects.filter(phone=phone).exists() if phone else False

        if email_exists and phone_exists:
            return Response(
                {"error": "The User with provided Mail Id and Phone number Already Exists use a different Mail Id and Phone number"},
                status=status.HTTP_400_BAD_REQUEST
            )
        elif email_exists:
            return Response(
                {"error": "The User with provided Mail Id Already Exists use a different Mail Id"},
                status=status.HTTP_400_BAD_REQUEST
            )
        elif phone_exists:
            return Response(
                {"error": "The User with provided Phone number Already Exists use a different Phone number"},
                status=status.HTTP_400_BAD_REQUEST
            )

        return super().create(request, *args, **kwargs)

class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        # Fetch the actual database user because the request.user from 
        # stateless JWT authentication only contains id, email, and role.
        return User.objects.get(id=self.request.user.id)

class VerifySessionView(views.APIView):
    """
    Stateless Heartbeat:
    Verifies the JWT is valid without hitting the database.
    Used for background liveness checks.
    """
    permission_classes = (permissions.IsAuthenticated,)

    def get(self, request):
        return Response({
            "success": True,
            "message": "Session is active",
            "data": {
                "user_id": request.user.id,
                "role": getattr(request.user, 'role', 'USER')
            }
        }, status=status.HTTP_200_OK)

# --- Membership & Payments ---

client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

class CreateRazorpayOrderView(views.APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        user = request.user

        # Prevent manual order if AutoPay is ENABLED
        existing_autopay = AutoPaySubscription.objects.filter(user=user, autopay_status='ENABLED').first()
        if existing_autopay:
            return Response({
                "success": False,
                "message": "AutoPay is active. Manual renewal not allowed.",
                "errors": "autopay_active"
            }, status=status.HTTP_400_BAD_REQUEST)

        amount = 5000 * 100  # Amount in paise (₹5000)
        
        order_data = {
            'amount': amount,
            'currency': 'INR',
            'payment_capture': 1 
        }
        
        try:
            razorpay_order = client.order.create(data=order_data)
            
            # Save the secure order reference
            PaymentOrder.objects.create(
                user=request.user,
                razorpay_order_id=razorpay_order.get("id"),
                amount=amount / 100, # Store in actual currency unit (₹)
                currency='INR',
                status="CREATED"
            )

            # Wrap in StandardizedResponse format
            return Response({
                "success": True,
                "message": "Order initiated successfully",
                "data": {
                    **razorpay_order,
                    "key_id": settings.RAZORPAY_KEY_ID
                }
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                "success": False,
                "message": "Failed to create order",
                "errors": str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class VerifyPaymentView(views.APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        # Fetch actual DB user because request.user is stateless
        user = User.objects.get(id=request.user.id)
        data = request.data
        
        razorpay_payment_id = data.get('razorpay_payment_id')
        razorpay_order_id = data.get('razorpay_order_id')
        razorpay_signature = data.get('razorpay_signature')

        # 1. Idempotency Check: Already processed?
        if Payment.objects.filter(transaction_id=razorpay_payment_id).exists():
            print(f"DEBUG: Verify - Payment already processed by webhook for {razorpay_payment_id}")
            return Response({
                "success": True,
                "message": "Payment already verified via backup webhook",
                "data": {
                    "transaction_id": razorpay_payment_id,
                }
            }, status=status.HTTP_200_OK)

        # 2. Validate Order exists and belongs to user
        order = PaymentOrder.objects.filter(
            razorpay_order_id=razorpay_order_id,
            user=user
        ).first()

        if not order:
            print(f"DEBUG: Verify failed - Order not found or user mismatch: {razorpay_order_id}")
            return Response({
                "success": False,
                "message": "Invalid or unauthorized order reference",
                "data": None
            }, status=status.HTTP_400_BAD_REQUEST)

        params_dict = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        }

        # 3. Signature Verification
        try:
            client.utility.verify_payment_signature(params_dict)
        except Exception:
            return Response({
                "success": False,
                "message": "Invalid payment signature.",
                "data": None
            }, status=status.HTTP_400_BAD_REQUEST)

        # 4. Fetch actual payment details
        try:
            payment_details = client.payment.fetch(razorpay_payment_id)
            raw_method = payment_details.get('method', 'CARD').upper()
            method_mapping = {
                'CARD': 'CARD',
                'UPI': 'UPI',
                'NETBANKING': 'NETBANKING',
                'WALLET': 'UPI',
            }
            final_payment_mode = method_mapping.get(raw_method, 'CARD')
        except Exception:
            final_payment_mode = 'CARD'

        # 5. Create Database Records inside transaction
        try:
            with transaction.atomic():
                current_date = timezone.now().date()
                existing_membership = Membership.objects.filter(user=user, status='ACTIVE').order_by('-end_date').first()
                
                start_date = current_date
                if existing_membership:
                    start_date = existing_membership.end_date + timezone.timedelta(days=1)

                membership = Membership.objects.create(
                    user=user,
                    plan_name='Membership Plan',
                    amount=order.amount,
                    start_date=start_date,
                    end_date=add_one_month(start_date),
                    status='ACTIVE'
                )

                payment = Payment.objects.create(
                    user=user,
                    membership=membership,
                    amount=order.amount,
                    payment_mode=final_payment_mode,
                    transaction_id=razorpay_payment_id,
                    payment_status='SUCCESS',
                    paid_at=timezone.now()
                )

                TransactionLedger.objects.create(
                    payment=payment,
                    user=user,
                    amount=order.amount,
                    transaction_type='CREDIT',
                    description=f"Verified {final_payment_mode} payment: {razorpay_payment_id}"
                )

                if user.status == 'PENDING':
                    user.status = 'ACTIVE'
                    user.save()

                # 6. Mark Order as COMPLETED
                order.status = "COMPLETED"
                order.save(update_fields=["status"])
                
            return Response({
                "success": True,
                "message": "Payment verified and membership activated",
                "data": {
                    "method_used": final_payment_mode,
                    "transaction_id": razorpay_payment_id,
                    "membership_end_date": membership.end_date
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                "success": False,
                "message": "Activation failed after payment confirmation",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

from django.utils.decorators import method_decorator


@method_decorator(csrf_exempt, name='dispatch')
class RazorpayWebhookView(APIView):
    """
    Backup processor:
    If the frontend verification fails (e.g. browser close), Razorpay will call this.
    """
    permission_classes = [] 

    def post(self, request):
        webhook_secret = getattr(settings, "RAZORPAY_WEBHOOK_SECRET", None)
        if not webhook_secret:
            return Response({"error": "Webhook secret not configured"}, status=status.HTTP_200_OK)

        received_signature = request.headers.get("X-Razorpay-Signature")
        body = request.body

        try:
            client.utility.verify_webhook_signature(
                body.decode('utf-8'),
                received_signature,
                webhook_secret
            )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        payload = json.loads(body)
        event = payload.get("event")

        if event == "payment.captured":
            payment_entity = payload["payload"]["payment"]["entity"]
            razorpay_payment_id = payment_entity["id"]
            razorpay_order_id = payment_entity["order_id"]

            if Payment.objects.filter(transaction_id=razorpay_payment_id).exists():
                return Response({"status": "already processed"}, status=status.HTTP_200_OK)

            order = PaymentOrder.objects.filter(
                razorpay_order_id=razorpay_order_id
            ).select_related('user').first()

            if not order:
                return Response({"status": "order not found"}, status=status.HTTP_200_OK)

            user = order.user

            with transaction.atomic():
                current_date = timezone.now().date()
                existing_membership = Membership.objects.filter(user=user, status='ACTIVE').order_by('-end_date').first()
                
                start_date = current_date
                if existing_membership:
                    start_date = existing_membership.end_date + timezone.timedelta(days=1)

                membership = Membership.objects.create(
                    user=user,
                    plan_name="Membership Plan",
                    amount=order.amount,
                    start_date=start_date,
                    end_date=add_one_month(start_date),
                    status="ACTIVE"
                )

                user.status = 'ACTIVE'
                user.save()

                payment = Payment.objects.create(
                    user=user,
                    membership=membership,
                    amount=order.amount,
                    payment_mode=payment_entity.get("method", "CARD").upper(),
                    transaction_id=razorpay_payment_id,
                    payment_status="SUCCESS",
                    paid_at=timezone.now()
                )

                TransactionLedger.objects.create(
                    payment=payment,
                    user=user,
                    amount=order.amount,
                    transaction_type="CREDIT",
                    description=f"Webhook verified payment {razorpay_payment_id}"
                )

                order.status = "COMPLETED"
                order.save(update_fields=["status"])

        return Response({"status": "event processed"}, status=status.HTTP_200_OK)

class MembershipDetailView(generics.RetrieveAPIView):
    serializer_class = MembershipDetailSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        membership = Membership.objects.filter(user=self.request.user, status='ACTIVE').order_by('-end_date').first()
        if not membership:
            # Fallback to expired if no active exists
            membership = Membership.objects.filter(user=self.request.user).order_by('-end_date').first()
        return membership

class UserTransactionListView(generics.ListAPIView):
    serializer_class = TransactionLedgerSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        return TransactionLedger.objects.filter(user=self.request.user).order_by('-transaction_date')

class AdminMarkAsPaidView(views.APIView):
    permission_classes = (permissions.IsAdminUser,)

    @transaction.atomic
    def post(self, request, user_id):
        try:
            target_user = User.objects.get(id=user_id)
            current_date = timezone.now().date()
            
            # Find existing active membership to extend, or create new
            existing_membership = Membership.objects.filter(user=target_user, status='ACTIVE').order_by('-end_date').first()
            start_date = current_date
            if existing_membership:
                start_date = existing_membership.end_date + timezone.timedelta(days=1)
                
            membership = Membership.objects.create(
                user=target_user,
                plan_name='Manual Admin Activation',
                amount=5000.00,  # Ensure correct mount
                start_date=start_date,
                end_date=add_one_month(start_date),
                status='ACTIVE'
            )
            
            payment = Payment.objects.create(
                user=target_user,
                membership=membership,
                amount=5000.00,
                payment_mode='MANUAL',
                transaction_id=f'MANUAL_{target_user.id}_{int(time.time())}',
                payment_status='SUCCESS',
                paid_at=timezone.now()
            )
            
            TransactionLedger.objects.create(
                payment=payment,
                user=target_user,
                amount=5000.00,
                transaction_type='CREDIT',
                description=f"Admin manual payment collection. User: {target_user.email}"
            )
            
            if target_user.status != 'ACTIVE':
                target_user.status = 'ACTIVE'
                target_user.save()
                
            return Response({'status': 'Member manually activated', 'user_id': target_user.id}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

# --- Vouchers ---
class VentureListView(generics.ListAPIView):
    serializer_class = VentureSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_queryset(self):
        return Venture.objects.filter(status='ACTIVE', is_deleted=False).prefetch_related('branches').order_by('name')

class RedeemVoucherAPIView(views.APIView):
    permission_classes = (permissions.IsAuthenticated,)

    @transaction.atomic
    def post(self, request):
        user = request.user
        venture_id = request.data.get('venture_id')
        branch_id = request.data.get('branch_id')
        bill_amount = request.data.get('bill_amount')
        
        if venture_id is None or branch_id is None or bill_amount is None:
            return Response({'error': 'venture_id, branch_id and bill_amount are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            from decimal import Decimal
            bill_amount_decimal = Decimal(str(bill_amount))
        except:
            return Response({'error': 'Invalid bill_amount'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            venture = Venture.objects.get(id=venture_id, status='ACTIVE', is_deleted=False)
        except Venture.DoesNotExist:
            return Response({'error': 'Venture not found or not active'}, status=status.HTTP_404_NOT_FOUND)

        try:
            branch = Branch.objects.get(id=branch_id, venture=venture)
        except Branch.DoesNotExist:
            return Response({'error': 'Branch not found'}, status=status.HTTP_404_NOT_FOUND)

        if venture.type == 'OWN':
            now = timezone.now()
            start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            if Redemption.objects.filter(user=user, venture=venture, redeemed_at__gte=start_of_month).exists():
                return Response({'error': 'Already redeemed this month'}, status=status.HTTP_400_BAD_REQUEST)

        from decimal import Decimal
        discount_amount = bill_amount_decimal * (venture.discount_percentage / Decimal('100.0'))
        final_paid_amount = bill_amount_decimal - discount_amount

        redemption = Redemption.objects.create(
            user=user,
            venture=venture,
            branch=branch,
            actual_bill_amount=bill_amount_decimal,
            discount_amount=discount_amount,
            final_paid_amount=final_paid_amount
        )

        return Response({
            'actual_bill_amount': redemption.actual_bill_amount,
            'discount_amount': redemption.discount_amount,
            'final_paid_amount': redemption.final_paid_amount,
            'branch_name': branch.branch_name,
            'redeemed_date': redemption.redeemed_at.strftime('%Y-%m-%d')
        }, status=status.HTTP_201_CREATED)

# --- Admin Dashboards ---

class AdminUserListView(generics.ListAPIView):
    serializer_class = UserSerializer
    permission_classes = (permissions.IsAdminUser,)

    def get_queryset(self):
        return User.objects.exclude(is_superuser=True).exclude(is_staff=True).exclude(id=self.request.user.id)

class AdminUserDeleteView(generics.DestroyAPIView):
    queryset = User.objects.all()
    permission_classes = (permissions.IsAdminUser,)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({'status': 'User deleted successfully'}, status=status.HTTP_200_OK)

    def perform_destroy(self, instance):
        if instance.status == 'ACTIVE':
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Cannot delete a user with ACTIVE account status.")
        instance.delete()

class AdminTransactionListView(generics.ListAPIView):
    queryset = TransactionLedger.objects.all()
    serializer_class = TransactionLedgerSerializer
    permission_classes = (permissions.IsAdminUser,)

    def get_queryset(self):
        queryset = super().get_queryset()
        user_id = self.request.query_params.get('user_id')
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')

        if user_id:
            queryset = queryset.filter(user_id=user_id)
        if start_date and end_date:
            queryset = queryset.filter(transaction_date__range=[start_date, end_date])
        return queryset

class AdminCollectionsView(views.APIView):
    permission_classes = (permissions.IsAdminUser,)

    def get(self, request):
        last_30_days = timezone.now() - timezone.timedelta(days=30)
        total = Payment.objects.filter(
            payment_status='SUCCESS', 
            paid_at__gte=last_30_days
        ).aggregate(models.Sum('amount'))['amount__sum'] or 0
        
        return Response({'total_last_30_days': total})

from django.db.models import Q, Sum
import csv
from django.http import HttpResponse

class AdminVentureListView(generics.ListCreateAPIView):
    serializer_class = AdminVentureSerializer
    permission_classes = (permissions.IsAdminUser,)

    def get_queryset(self):
        queryset = Venture.objects.filter(is_deleted=False).order_by('-created_at')
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | 
                Q(branches__branch_name__icontains=search)
            ).distinct()
        return queryset

    @transaction.atomic
    def perform_create(self, serializer):
        # Prevent Django from saving files to local storage by removing them from validated_data
        poster_file = serializer.validated_data.pop('poster', None)
        icon_file = serializer.validated_data.pop('icon', None)
        
        venture = serializer.save()
        
        if poster_file:
            try:
                res = cloudinary.uploader.upload(
                    poster_file, 
                    folder="club369/ventures",
                    quality="auto",
                    fetch_format="auto"
                )
                venture.poster = res.get('secure_url')
                venture.poster_public_id = res.get('public_id')
            except Exception as e:
                logger.error(f"Cloudinary poster upload failed: {e}")
                
        if icon_file:
            try:
                res = cloudinary.uploader.upload(
                    icon_file, 
                    folder="club369/ventures",
                    quality="auto",
                    fetch_format="auto"
                )
                venture.icon = res.get('secure_url')
                venture.icon_public_id = res.get('public_id')
            except Exception as e:
                logger.error(f"Cloudinary icon upload failed: {e}")
                
        if poster_file or icon_file:
            venture.save()

        # Handle branches if provided as JSON string
        raw_branches = self.request.data.get('branches', '[]')
        if isinstance(raw_branches, str):
            import json
            try:
                branches_data = json.loads(raw_branches)
            except:
                branches_data = []
        else:
            branches_data = raw_branches
            
        for b_name in branches_data:
            if b_name and isinstance(b_name, str):
                Branch.objects.create(venture=venture, branch_name=b_name.strip())

class AdminVentureDetailView(generics.RetrieveUpdateAPIView):
    serializer_class = AdminVentureSerializer
    permission_classes = (permissions.IsAdminUser,)
    queryset = Venture.objects.filter(is_deleted=False)

    @transaction.atomic
    def perform_update(self, serializer):
        # Prevent Django from saving files to local storage by removing them from validated_data
        poster_file = serializer.validated_data.pop('poster', None)
        icon_file = serializer.validated_data.pop('icon', None)
        
        venture = serializer.save()
        
        if poster_file:
            if venture.poster_public_id:
                try:
                    cloudinary.uploader.destroy(venture.poster_public_id)
                except Exception as e:
                    logger.error(f"Cloudinary poster deletion failed: {e}")
            try:
                res = cloudinary.uploader.upload(
                    poster_file, 
                    folder="club369/ventures",
                    quality="auto",
                    fetch_format="auto"
                )
                venture.poster = res.get('secure_url')
                venture.poster_public_id = res.get('public_id')
            except Exception as e:
                logger.error(f"Cloudinary poster upload failed: {e}")
                
        if icon_file:
            if venture.icon_public_id:
                try:
                    cloudinary.uploader.destroy(venture.icon_public_id)
                except Exception as e:
                    logger.error(f"Cloudinary icon deletion failed: {e}")
            try:
                res = cloudinary.uploader.upload(
                    icon_file, 
                    folder="club369/ventures",
                    quality="auto",
                    fetch_format="auto"
                )
                venture.icon = res.get('secure_url')
                venture.icon_public_id = res.get('public_id')
            except Exception as e:
                logger.error(f"Cloudinary icon upload failed: {e}")
                
        if poster_file or icon_file:
            venture.save()

        if 'branches' in self.request.data:
            raw_branches = self.request.data.get('branches', '[]')
            if isinstance(raw_branches, str):
                import json
                try:
                    branches_data = json.loads(raw_branches)
                except:
                    branches_data = [] # Invalid JSON
            else:
                branches_data = raw_branches
                
            Branch.objects.filter(venture=venture).delete()
            for b_name in branches_data:
                if b_name and isinstance(b_name, str):
                    Branch.objects.create(venture=venture, branch_name=b_name.strip())

class AdminVentureToggleView(views.APIView):
    permission_classes = (permissions.IsAdminUser,)

    def patch(self, request, pk):
        try:
            venture = Venture.objects.get(pk=pk, is_deleted=False)
            venture.status = 'SUSPENDED' if venture.status == 'ACTIVE' else 'ACTIVE'
            venture.save()
            return Response({'status': 'Venture status updated', 'current_status': venture.status})
        except Venture.DoesNotExist:
            return Response({'error': 'Venture not found'}, status=status.HTTP_404_NOT_FOUND)

class AdminVentureDeleteView(views.APIView):
    permission_classes = (permissions.IsAdminUser,)

    def delete(self, request, pk):
        try:
            venture = Venture.objects.get(pk=pk, is_deleted=False)
            venture.is_deleted = True
            venture.save()
            return Response({'status': 'Venture deleted'})
        except Venture.DoesNotExist:
            return Response({'error': 'Venture not found'}, status=404)

class AdminRedemptionReportView(generics.ListAPIView):
    serializer_class = RedemptionSerializer
    permission_classes = (permissions.IsAdminUser,)

    def get_queryset(self):
        queryset = Redemption.objects.all().order_by('-redeemed_at')
        scope = self.request.query_params.get('scope', 'all')
        
        now = timezone.now()
        if scope == 'current_month':
            start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            queryset = queryset.filter(redeemed_at__gte=start_of_month)
        elif scope == 'custom':
            from_date = self.request.query_params.get('from_date')
            to_date = self.request.query_params.get('to_date')
            if from_date:
                queryset = queryset.filter(redeemed_at__gte=from_date)
            if to_date:
                queryset = queryset.filter(redeemed_at__lte=to_date)
                
        branch_id = self.request.query_params.get('branch_id')
        if branch_id:
            queryset = queryset.filter(branch_id=branch_id)
            
        venture_id = self.request.query_params.get('venture_id')
        if venture_id:
            queryset = queryset.filter(venture_id=venture_id)
            
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        
        if request.query_params.get('export') == 'excel':
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="redemptions.csv"'
            writer = csv.writer(response)
            writer.writerow(['S.No', 'User Name', 'Branch Name', 'Actual Bill Amount', 'Discount Amount', 'Final Paid Amount', 'Redeemed Date'])
            
            total_bill = 0
            total_discount = 0
            total_final = 0
            
            for idx, r in enumerate(queryset, 1):
                writer.writerow([
                    idx,
                    r.user.full_name,
                    r.branch.branch_name,
                    r.actual_bill_amount,
                    r.discount_amount,
                    r.final_paid_amount,
                    r.redeemed_at.strftime('%Y-%m-%d') if r.redeemed_at else ''
                ])
                total_bill += r.actual_bill_amount
                total_discount += r.discount_amount
                total_final += r.final_paid_amount
                
            writer.writerow(['TOTAL', '', '', str(total_bill), str(total_discount), str(total_final), ''])
            return response
            
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            response = self.get_paginated_response(serializer.data)
            
            totals = queryset.aggregate(
                total_bill=Sum('actual_bill_amount'),
                total_discount=Sum('discount_amount'),
                total_collected=Sum('final_paid_amount')
            )
            response.data['totals'] = {
                'total_bill': totals['total_bill'] or 0,
                'total_discount': totals['total_discount'] or 0,
                'total_collected': totals['total_collected'] or 0,
            }
            return response

        serializer = self.get_serializer(queryset, many=True)
        totals = queryset.aggregate(
            total_bill=Sum('actual_bill_amount'),
            total_discount=Sum('discount_amount'),
            total_collected=Sum('final_paid_amount')
        )
        return Response({
            'results': serializer.data,
            'totals': {
                'total_bill': totals['total_bill'] or 0,
                'total_discount': totals['total_discount'] or 0,
                'total_collected': totals['total_collected'] or 0,
            }
        })

class AdminMarkAsPaidView(views.APIView):
    permission_classes = (permissions.IsAdminUser,)

    @transaction.atomic
    def post(self, request, user_id):
        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # Prevent manual extension if AutoPay is ENABLED
        existing_autopay = AutoPaySubscription.objects.filter(user=user, autopay_status='ENABLED').first()
        if existing_autopay:
            return Response({'error': 'AutoPay is active. Manual renewal not allowed.'}, status=status.HTTP_400_BAD_REQUEST)

        amount = request.data.get('amount', 5000.00)
        
        current_date = timezone.now().date()
        existing_membership = Membership.objects.filter(user=user, status='ACTIVE').order_by('-end_date').first()
        
        start_date = current_date
        if existing_membership and existing_membership.end_date >= current_date:
            start_date = existing_membership.end_date + timezone.timedelta(days=1)

        end_date = add_one_month(start_date)
        
        membership = Membership.objects.create(
            user=user,
            plan_name='Manual Membership Extension',
            amount=amount,
            start_date=start_date,
            end_date=end_date,
            status='ACTIVE'
        )

        txn_id = f"MANUAL_{user_id}_{int(time.time())}"

        payment = Payment.objects.create(
            user=user,
            membership=membership,
            amount=amount,
            payment_mode='MANUAL',
            transaction_id=txn_id,
            payment_status='SUCCESS',
            paid_at=timezone.now()
        )

        TransactionLedger.objects.create(
            payment=payment,
            user=user,
            amount=amount,
            transaction_type='CREDIT',
            description=f"Admin manual payment collection. User: {user.email}"
        )

        if user.status == 'PENDING':
            user.status = 'ACTIVE'
            user.save(update_fields=['status'])

        return Response({
            'status': 'Manual payment marked successfully',
            'membership_end_date': end_date
        }, status=status.HTTP_200_OK)

# --- Profile Picture Management (Cloudinary) ---

class GetUploadSignatureView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        timestamp = int(time.time())
        folder = f"club369/profile_pics/{request.user.id}"
        transformation = "c_fill,w_200,h_200,q_auto:good"

        params_to_sign = {
            "timestamp": timestamp,
            "folder": folder,
            "transformation": transformation
        }

        signature = cloudinary.utils.api_sign_request(
            params_to_sign,
            os.getenv("CLOUDINARY_API_SECRET")
        )

        return Response({
            "cloud_name": os.getenv("CLOUDINARY_CLOUD_NAME"),
            "api_key": os.getenv("CLOUDINARY_API_KEY"),
            "timestamp": timestamp,
            "signature": signature,
            "folder": folder,
            "transformation": transformation
        })

class SaveProfilePicView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Fetch actual DB user because request.user is stateless
        user = User.objects.get(id=request.user.id)
        new_url = request.data.get("secure_url")
        new_public_id = request.data.get("public_id")

        if not new_url or not new_public_id:
            return Response({
                "status": "error",
                "message": "Invalid image data"
            }, status=status.HTTP_400_BAD_REQUEST)

        # Delete old image if exists
        if user.profile_pic_public_id:
            try:
                cloudinary.uploader.destroy(user.profile_pic_public_id)
            except Exception:
                pass  # Avoid breaking flow

        # Save new image metadata
        user.profile_pic = new_url
        user.profile_pic_public_id = new_public_id
        user.save()

        return Response({
            "status": "success",
            "message": "Profile picture updated",
            "image_url": new_url
        }, status=status.HTTP_200_OK)


# Password Reset Views

class ForgotPasswordView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        user = User.objects.filter(email=email).first()
        
        # If user exists, send password link
        if user:
            token = default_token_generator.make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            
            # This link points to your React frontend route (using HashRouter #/)
            reset_url = f"{settings.FRONTEND_URL.rstrip('/')}/#/password-reset/{uidb64}/{token}"
            
            send_mail(
                subject='Password Reset Request - CLUB369',
                message=f'Click the link below to reset your password. It is valid for 24 hours:\n\n{reset_url}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
        
            return Response({"message": "A reset link has been sent to your email address."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "User with this mail ID not exists"}, status=status.HTTP_404_NOT_FOUND)

class PasswordResetConfirmView(views.APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user and default_token_generator.check_token(user, token):
            new_password = request.data.get('password')
            if check_password(new_password, user.password):
                return Response({"error": "New password cannot be similar to the old passwords"}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(new_password)
            user.save()
            # default_token_generator.delete(user, token)
            return Response({"message": "Password updated successfully!"}, status=status.HTTP_200_OK)
        
        return Response({"error": "The password reset link is invalid, malformed, or has expired. Please request a new one."}, status=status.HTTP_400_BAD_REQUEST)
  
# --- AutoPay Subscriptions MVP ---


class EnableAutoPayView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        # Prevent if already enabled
        existing = AutoPaySubscription.objects.filter(user=user, autopay_status='ENABLED').first()
        if existing:
            return Response({'error': 'AutoPay is already enabled'}, status=status.HTTP_400_BAD_REQUEST)

        # 1. Create Razorpay Plan if needed, or assume you have a base PLAN_ID
        # Hardcoding generic subscription details for MVP based on 5000 monthly
        # Note: You need a real plan_id from your Razorpay Dashboard in production.
        PLAN_ID = os.getenv('RAZORPAY_AUTOPAY_PLAN_ID') 
        if not PLAN_ID:
            return Response({'error': 'Server misconfiguration: No Plan ID'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        try:
            subscription = client.subscription.create({
                "plan_id": PLAN_ID,
                "customer_notify": 1,
                "total_count": 12, # 1 year validity assumed
                "notes": {
                    "user_id": user.id,
                }
            })

            AutoPaySubscription.objects.create(
                user=user,
                razorpay_subscription_id=subscription.get('id'),
                autopay_status='PENDING',
                current_cycle_status='UNPAID'
            )

            return Response({
                "success": True,
                "message": "AutoPay subscription created",
                "data": {
                    "subscription_id": subscription.get('id'),
                    "key_id": settings.RAZORPAY_KEY_ID
                }
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class CancelAutoPayView(views.APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        user = request.user
        subscription = AutoPaySubscription.objects.filter(user=user, autopay_status='ENABLED').first()
        
        if not subscription:
            return Response({'error': 'No active AutoPay subscription found'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            client.subscription.cancel(subscription.razorpay_subscription_id)
            subscription.autopay_status = 'CANCELLED'
            subscription.save()

            return Response({"message": "AutoPay cancelled successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class AutoPayVerifyPaymentView(views.APIView):
    """
    Immediate Payment Verification After Razorpay Checkout for AutoPay
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        # Fetch actual DB user because request.user is stateless
        user = User.objects.get(id=request.user.id)
        payment_id = request.data.get('payment_id')
        subscription_id = request.data.get('subscription_id')
        signature = request.data.get('signature')

        if not payment_id or not subscription_id or not signature:
            logger.error("autopay_signature_verification_failed: missing parameters")
            return Response({"error": "Missing parameters"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            client.utility.verify_subscription_payment_signature({
                'razorpay_subscription_id': subscription_id,
                'razorpay_payment_id': payment_id,
                'razorpay_signature': signature
            })
            logger.info(f"autopay_signature_verified for subscription {subscription_id}")
        except razorpay.errors.SignatureVerificationError:
            logger.error(f"autopay_signature_verification_failed for subscription {subscription_id}")
            return Response({"error": "Invalid signature"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Ensure Idempotency
        if Payment.objects.filter(transaction_id=payment_id).exists():
            return Response({"status": "already processed", "message": "Access already granted"}, status=status.HTTP_200_OK)

        sub = AutoPaySubscription.objects.filter(razorpay_subscription_id=subscription_id).first()
        if not sub:
            return Response({"error": "Subscription not found"}, status=status.HTTP_404_NOT_FOUND)

        # Get actual payment amount
        try:
            pmt = client.payment.fetch(payment_id)
            amount = pmt.get('amount', 0) / 100
        except Exception:
            amount = 5000.00 # fallback

        with transaction.atomic():
            sub.autopay_status = 'ENABLED'
            sub.current_cycle_status = 'PAID'
            sub.last_payment_date = timezone.now()
            sub.save()

            if user.status == 'PENDING':
                user.status = 'ACTIVE'
                user.save()

            # Extend or Create Membership for this billing cycle
            current_date = timezone.now().date()
            existing_membership = Membership.objects.filter(user=user, status='ACTIVE').order_by('-end_date').first()
            
            start_date = current_date
            if existing_membership:
                start_date = existing_membership.end_date + timezone.timedelta(days=1)

            membership = Membership.objects.create(
                user=user,
                plan_name='AutoPay Membership',
                amount=amount,
                start_date=start_date,
                end_date=add_one_month(start_date),
                status='ACTIVE',
                auto_pay_enabled=True
            )
            
            payment = Payment.objects.create(
                user=user,
                membership=membership,
                amount=amount,
                payment_mode='AUTOPAY',
                transaction_id=payment_id,
                payment_status="SUCCESS",
                paid_at=timezone.now()
            )

            TransactionLedger.objects.create(
                payment=payment,
                user=user,
                amount=amount,
                transaction_type="CREDIT",
                description=f"AutoPay instant verified: {payment_id}"
            )
        
        logger.info(f"autopay_checkout_success and premium activated for {user.email}")
        return Response({"status": "success", "message": "Premium access activated instantly"}, status=status.HTTP_200_OK)

@method_decorator(csrf_exempt, name='dispatch')
class RazorpayAutoPayWebhookView(APIView):
    """
    Dedicated webhook specifically for handling AutoPay Subscriptions events.
    """
    permission_classes = [] 

    def post(self, request):
        webhook_secret = getattr(settings, "RAZORPAY_WEBHOOK_SECRET", None)
        if not webhook_secret:
            return Response({"error": "Webhook secret not configured"}, status=status.HTTP_200_OK)

        received_signature = request.headers.get("X-Razorpay-Signature")
        body = request.body

        try:
            client.utility.verify_webhook_signature(
                body.decode('utf-8'),
                received_signature,
                webhook_secret
            )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

        payload = json.loads(body)
        # print("WEBHOOK PAYLOAD RECEIVED:", json.dumps(payload, indent=2))
        event = payload.get("event")

        # Handle subscription charged
        # For Razorpay Subscriptions, the primary success event is subscription.charged.
        # It contains both the subscription entity and the payment entity.
        if event in ["subscription.charged", "payment.captured"]:
            # Extract payment entity
            payment_entity = payload.get("payload", {}).get("payment", {}).get("entity", {})
            razorpay_payment_id = payment_entity.get("id")
            amount = payment_entity.get("amount", 0) / 100
            
            # Extract subscription entity (present in subscription.charged)
            subscription_entity = payload.get("payload", {}).get("subscription", {}).get("entity", {})
            sub_id = subscription_entity.get("id") or payment_entity.get("subscription_id")
            
            # Notes are attached to the subscription, not the payment
            notes = subscription_entity.get("notes", {}) or payment_entity.get("notes", {})
            user_id = notes.get("user_id") if isinstance(notes, dict) else None
            
            sub = None
            if sub_id:
                sub = AutoPaySubscription.objects.filter(razorpay_subscription_id=sub_id).first()
            elif user_id:
                sub = AutoPaySubscription.objects.filter(user_id=user_id, autopay_status__in=['ENABLED', 'PENDING']).first()

            if not sub:
                return Response({"status": "subscription not found"}, status=status.HTTP_200_OK)

            if Payment.objects.filter(transaction_id=razorpay_payment_id).exists():
                return Response({"status": "already processed"}, status=status.HTTP_200_OK)

            with transaction.atomic():
                sub.autopay_status = 'ENABLED'
                sub.current_cycle_status = 'PAID'
                sub.last_payment_date = timezone.now()
                sub.save()

                user = sub.user

                if user.status == 'PENDING':
                    user.status = 'ACTIVE'
                    user.save()

                # Extend or Create Membership for this billing cycle
                current_date = timezone.now().date()
                existing_membership = Membership.objects.filter(user=user, status='ACTIVE').order_by('-end_date').first()
                
                start_date = current_date
                if existing_membership:
                    start_date = existing_membership.end_date + timezone.timedelta(days=1)

                membership = Membership.objects.create(
                    user=user,
                    plan_name='AutoPay Membership',
                    amount=amount,
                    start_date=start_date,
                    end_date=add_one_month(start_date),
                    status='ACTIVE',
                    auto_pay_enabled=True
                )
                
                payment = Payment.objects.create(
                    user=user,
                    membership=membership,
                    amount=amount,
                    payment_mode='AUTOPAY',
                    transaction_id=razorpay_payment_id,
                    payment_status="SUCCESS",
                    paid_at=timezone.now()
                )

                TransactionLedger.objects.create(
                    payment=payment,
                    user=user,
                    amount=amount,
                    transaction_type="CREDIT",
                    description=f"AutoPay captured: {razorpay_payment_id}"
                )

        # Handle subscription failed
        elif event == "payment.failed":
            # For AutoPay, failed payments should mark cycle as UNPAID
            payment_entity = payload.get("payload", {}).get("payment", {}).get("entity", {})
            notes = payment_entity.get("notes", {})
            user_id = notes.get("user_id") if isinstance(notes, dict) else None
            
            sub = None
            if user_id:
                sub = AutoPaySubscription.objects.filter(user_id=user_id, autopay_status__in=['ENABLED', 'PENDING']).first()
            if not sub and "subscription_id" in payment_entity:
                sub = AutoPaySubscription.objects.filter(razorpay_subscription_id=payment_entity["subscription_id"]).first()

            if sub:
                sub.current_cycle_status = 'UNPAID'
                sub.save()

        # Handle subscription cancelled remotely
        elif event == "subscription.cancelled":
            subscription_entity = payload.get("payload", {}).get("subscription", {}).get("entity", {})
            subscription_id = subscription_entity.get("id")
            
            sub = AutoPaySubscription.objects.filter(razorpay_subscription_id=subscription_id).first()
            if sub:
                sub.autopay_status = 'CANCELLED'
                sub.save()

        return Response({"status": "autopay event processed"}, status=status.HTTP_200_OK)