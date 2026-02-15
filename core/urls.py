from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    RegisterView, LogoutView, UserProfileView, VoucherListView, ClaimVoucherView,
    AdminUserListView, AdminTransactionListView, AdminCollectionsView, LoginView,
    CustomTokenRefreshView, MembershipDetailView, UserTransactionListView,
    AdminVoucherListView, AdminVoucherCreateView, AdminVoucherDeleteView, AdminVoucherToggleView,
    AdminUserDeleteView, CreateRazorpayOrderView, VerifyPaymentView, RazorpayWebhookView,
    GetUploadSignatureView, SaveProfilePicView
)


urlpatterns = [
    # Auth
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('auth/me/', UserProfileView.as_view(), name='me'),

    # Membership & Payment
    path('payments/webhook/', RazorpayWebhookView.as_view(), name='razorpay-webhook'),
    # Step 1: Initialize the payment
    path('payments/create-order/', CreateRazorpayOrderView.as_view(), name='create-razorpay-order'),
    # Step 2: Confirm the payment
    path('payments/verify/', VerifyPaymentView.as_view(), name='verify-payment'),
    # path('payments/create/', CreatePaymentView.as_view(), name='create-payment'),
    path('membership/details/', MembershipDetailView.as_view(), name='membership-details'),
    path('membership/transactions/', UserTransactionListView.as_view(), name='membership-transactions'),

    # Profile Picture Management
    path('profile/upload-signature/', GetUploadSignatureView.as_view(), name='get-upload-signature'),
    path('profile/save-picture/', SaveProfilePicView.as_view(), name='save-profile-pic'),

    # Vouchers

    path('vouchers/', VoucherListView.as_view(), name='voucher-list'),
    path('vouchers/claim/<int:voucher_id>/', ClaimVoucherView.as_view(), name='voucher-claim'),

    # Admin
    path('admin/users/', AdminUserListView.as_view(), name='admin-users'),
    path('admin/transactions/', AdminTransactionListView.as_view(), name='admin-transactions'),
    path('admin/collections/', AdminCollectionsView.as_view(), name='admin-collections'),
    path('admin/vouchers/', AdminVoucherListView.as_view(), name='admin-voucher-list'),
    path('admin/vouchers/create/', AdminVoucherCreateView.as_view(), name='admin-voucher-create'),
    path('admin/vouchers/<int:pk>/toggle/', AdminVoucherToggleView.as_view(), name='admin-voucher-toggle'),
    path('admin/vouchers/<int:pk>/delete/', AdminVoucherDeleteView.as_view(), name='admin-voucher-delete'),
    path('admin/users/<int:pk>/delete/', AdminUserDeleteView.as_view(), name='admin-user-delete'),
]
