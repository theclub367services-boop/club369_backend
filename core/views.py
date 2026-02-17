from django.contrib.auth import login, logout
from rest_framework import status, generics, permissions, views
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.utils import timezone
from django.db import transaction
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User, Membership, Payment, TransactionLedger, Voucher, UserVoucher, AdminActivityLog, PaymentOrder
from .serializers import (
    UserSerializer, RegisterSerializer, 
    MembershipSerializer, PaymentSerializer, TransactionLedgerSerializer, 
    VoucherSerializer, UserVoucherSerializer, AdminActivityLogSerializer,
    MembershipDetailSerializer, AdminVoucherSerializer
)
from django.conf import settings
import os
import razorpay
import json
import time
import cloudinary.utils
import cloudinary.uploader
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes

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

        # 2. User Session Creation
        login(request, user)

        # 3. Token Generation
        refresh = RefreshToken.for_user(user)
        
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
        
        # Inject into request data for parent view
        request.data['refresh'] = refresh_token
        
        # 2 & 3. Validation and Rotation (via parent view)
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # 4. Session Re-Bridging
            request.session['jwt_tokens'] = {
                'access': response.data.get('access'),
                'refresh': response.data.get('refresh')
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
        # 1. Session Invalidation
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

class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def get_object(self):
        return self.request.user

# --- Membership & Payments ---

client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

class CreateRazorpayOrderView(views.APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):
        amount =4999 * 100 
        
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
        user = request.user
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
                    end_date=start_date + timezone.timedelta(days=30),
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
                    end_date=start_date + timezone.timedelta(days=30),
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

# class CreatePaymentView(views.APIView):
#     permission_classes = (permissions.IsAuthenticated,)

#     @transaction.atomic
#     def post(self, request):
#         user = request.user
#         # Allow users with 'PENDING' or 'ACTIVE' status (standard renewals)
#         if user.status not in ['PENDING', 'ACTIVE']:
#             return Response({'error': f'User account status {user.status} does not allow payments'}, status=status.HTTP_403_FORBIDDEN)

#         current_date = timezone.now().date()
        
#         # Check for existing active membership
#         existing_membership = Membership.objects.filter(user=user, status='ACTIVE').order_by('-end_date').first()
        
#         start_date = current_date
        
#         if existing_membership:
#             # Rule 1: Renewal Window Enforcement (5 days before end_date)
#             renewal_allowed_date = existing_membership.end_date - timezone.timedelta(days=5)
            
#             if current_date < renewal_allowed_date:
#                 return Response(
#                     {"error": "Membership already active or payment already processed"}, 
#                     status=status.HTTP_400_BAD_REQUEST
#                 )
            
#             # Rule 2: Duplicate Payment Protection
#             # Check if a successful payment already exists for the renewal of this membership
#             # (i.e., a membership starting after the current one)
#             if Membership.objects.filter(user=user, start_date=existing_membership.end_date + timezone.timedelta(days=1)).exists():
#                  return Response(
#                     {"error": "Membership already active or payment already processed"}, 
#                     status=status.HTTP_400_BAD_REQUEST
#                 )

#             # Renewal Flow: new_start_date = current_end_date + 1
#             start_date = existing_membership.end_date + timezone.timedelta(days=1)

#         data = request.data
#         membership_data = data.get('membership', {})
#         payment_data = data.get('payment', {})

#         # Create Membership
#         # Default duration is 30 days as per renewal logic instruction
#         end_date = start_date + timezone.timedelta(days=30)
        
#         membership = Membership.objects.create(
#             user=user,
#             plan_name=membership_data.get('plan_name', 'Standard Renewal'),
#             amount=membership_data.get('amount', 0),
#             start_date=start_date,
#             end_date=end_date,
#             status='ACTIVE'
#         )

#         # Create Payment
#         payment = Payment.objects.create(
#             user=user,
#             membership=membership,
#             amount=payment_data.get('amount', 0),
#             payment_mode=payment_data.get('payment_mode', 'UPI'),
#             transaction_id=payment_data.get('transaction_id'),
#             payment_status='SUCCESS', # Mock successful payment for MVP
#             paid_at=timezone.now()
#         )

#         # Create Ledger Entry
#         TransactionLedger.objects.create(
#             payment=payment,
#             user=user,
#             amount=payment.amount,
#             transaction_type='CREDIT',
#             description=f"Membership payment for {membership.plan_name}"
#         )

#         # Update user status to ACTIVE if it was PENDING
#         if user.status == 'PENDING':
#             user.status = 'ACTIVE'
#             user.save()

#         return Response({
#             'status': 'Payment processed successfully', 
#             'membership_id': membership.id,
#             'start_date': start_date,
#             'end_date': end_date
#         })

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

# --- Vouchers ---


class VoucherListView(generics.ListAPIView):
    queryset = Voucher.objects.filter(is_active=True)
    serializer_class = VoucherSerializer
    permission_classes = (permissions.IsAuthenticated,)

class ClaimVoucherView(views.APIView):
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request, voucher_id):
        try:
            voucher = Voucher.objects.get(id=voucher_id, is_active=True)
            
            # Check if already claimed
            if UserVoucher.objects.filter(user=request.user, voucher=voucher).exists():
                return Response({'error': 'Voucher already claimed'}, status=status.HTTP_400_BAD_REQUEST)

            UserVoucher.objects.create(user=request.user, voucher=voucher)
            serializer = VoucherSerializer(voucher, context={'request': request})
            return Response(serializer.data)
        except Voucher.DoesNotExist:
            return Response({'error': 'Voucher not found'}, status=status.HTTP_404_NOT_FOUND)

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

class AdminVoucherListView(generics.ListAPIView):
    queryset = Voucher.objects.all().order_by('-created_at')
    serializer_class = AdminVoucherSerializer
    permission_classes = (permissions.IsAdminUser,)

class AdminVoucherCreateView(generics.CreateAPIView):
    queryset = Voucher.objects.all()
    serializer_class = AdminVoucherSerializer
    permission_classes = (permissions.IsAdminUser,)

    def perform_create(self, serializer):
        # Default valid_from to now if not provided
        if 'valid_from' not in serializer.validated_data:
            serializer.save(valid_from=timezone.now())
        else:
            serializer.save()

class AdminVoucherToggleView(views.APIView):
    permission_classes = (permissions.IsAdminUser,)

    def patch(self, request, pk):
        try:
            voucher = Voucher.objects.get(pk=pk)
            voucher.is_active = not voucher.is_active
            voucher.save()
            return Response({'status': 'Voucher status updated', 'is_active': voucher.is_active})
        except Voucher.DoesNotExist:
            return Response({'error': 'Voucher not found'}, status=status.HTTP_404_NOT_FOUND)
class AdminVoucherDeleteView(views.APIView):
    permission_classes = (permissions.IsAdminUser,)

    def delete(self, request, pk):
        try:
            voucher = Voucher.objects.get(pk=pk)
            voucher.delete()
            return Response({'status': 'Voucher deleted'})
        except Voucher.DoesNotExist:
            return Response({'error': 'Voucher not found'}, status=404)

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
        user = request.user
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

