from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import (
    RegisterView, LogoutView, UserProfileView, VentureListView, RedeemVoucherAPIView,
    AdminUserListView, AdminTransactionListView, AdminCollectionsView, LoginView,
    CustomTokenRefreshView, MembershipDetailView, UserTransactionListView,
    AdminVentureListView, AdminVentureDetailView, AdminVentureDeleteView, AdminVentureToggleView, AdminRedemptionReportView,
    AdminUserDeleteView, CreateRazorpayOrderView, VerifyPaymentView, RazorpayWebhookView,
    GetUploadSignatureView, SaveProfilePicView, AdminMarkAsPaidView,
    EnableAutoPayView, CancelAutoPayView, RazorpayAutoPayWebhookView, AutoPayVerifyPaymentView,ForgotPasswordView,PasswordResetConfirmView,
    VerifySessionView
)


urlpatterns = [
    # Auth
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', LoginView.as_view(), name='login'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('auth/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('auth/me/', UserProfileView.as_view(), name='me'),
    path('auth/verify-session/', VerifySessionView.as_view(), name='verify-session'),

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

    path('vouchers/ventures/', VentureListView.as_view(), name='venture-list'),
    path('vouchers/redeem/', RedeemVoucherAPIView.as_view(), name='venture-redeem'),

    # Admin
    path('admin/users/', AdminUserListView.as_view(), name='admin-users'),
    path('admin/transactions/', AdminTransactionListView.as_view(), name='admin-transactions'),
    path('admin/collections/', AdminCollectionsView.as_view(), name='admin-collections'),
    path('admin/vouchers/ventures/', AdminVentureListView.as_view(), name='admin-venture-list'),
    path('admin/vouchers/ventures/<int:pk>/', AdminVentureDetailView.as_view(), name='admin-venture-detail'),
    path('admin/vouchers/ventures/<int:pk>/toggle/', AdminVentureToggleView.as_view(), name='admin-venture-toggle'),
    path('admin/vouchers/ventures/<int:pk>/delete/', AdminVentureDeleteView.as_view(), name='admin-venture-delete'),
    path('admin/vouchers/redemptions/', AdminRedemptionReportView.as_view(), name='admin-redemption-report'),
    path('admin/users/<int:pk>/delete/', AdminUserDeleteView.as_view(), name='admin-user-delete'),
    path('admin/mark-as-paid/<int:user_id>/', AdminMarkAsPaidView.as_view(), name='admin-mark-paid'),

    # AutoPay Subscriptions MVP
    path('autopay/enable/', EnableAutoPayView.as_view(), name='autopay-enable'),
    path('autopay/cancel/', CancelAutoPayView.as_view(), name='autopay-cancel'),
    path('autopay/webhook/', RazorpayAutoPayWebhookView.as_view(), name='autopay-webhook'),
    path('autopay/verify-payment/', AutoPayVerifyPaymentView.as_view(), name='autopay-verify-payment'),

        #Forget Password
    path('auth/password/reset/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('auth/password/reset/confirm/<uidb64>/<token>/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),

]
