from django.urls import path
from .views import MerchantSignupView, MerchantLoginView, CreatePaymentView, SendOTPView, ValidateOTPView,  APIKeyListView
from .views import GenerateAPIKeyView, RevokeAPIKeyView, ListPaymentOrdersView, CancelPaymentOrderView, CreateDeepLinkView, CreateQRCodeView, PaymentsDashboardView
from .views import CollectPayView, CheckOrderStatusView, DashboardView, DashboardV2View, RefundDashboardView, MainDashboardView, UpdateMerchantProfileView
from .views import ForgotPasswordView, ResetPasswordView

from gateway.views import VerifyPANView, VerifyGSTView, GSTSignatoryView, VerifyPaymentView, InitiateRefundView

from .views import PanImageVerifyView, GstImageVerifyView
from .views import WebhookAPIView
from .views import TestEncryptKeyView


urlpatterns = [
    # Merchant auth
    path('signup/merchant/', MerchantSignupView.as_view(), name='merchant-signup'),
    path('merchant/login/', MerchantLoginView.as_view(), name='merchant-login'),
    path('merchant/update-profile/', UpdateMerchantProfileView.as_view(), name='update-profile'),

    # OTP
    path("otp/send/", SendOTPView.as_view(), name="otp-send"),
    path("otp/verify/", ValidateOTPView.as_view(), name="otp-verify"),

    # API Keys
    path("api-keys/generate/", GenerateAPIKeyView.as_view(), name="generate_api_key"),
    path("api-keys/", APIKeyListView.as_view(), name="list_api_keys"),
    path("api-keys/<str:key_id>/revoke/", RevokeAPIKeyView.as_view(), name="revoke_api_key"),

    # Payments
    path('v1/payments/create/', CreatePaymentView.as_view(), name='payment-create'),
    path('v1/payments/orders/', ListPaymentOrdersView.as_view(), name='payment-orders-list'),
    path('v1/payments/cancel/', CancelPaymentOrderView.as_view(), name='payment-orders-cancel'),
    path('v1/payments/deeplink/', CreateDeepLinkView.as_view(), name='payment-orders-deeplink'),
    path('v1/payments/qrcode/', CreateQRCodeView.as_view(), name="payment-qrcode"),
    path('v1/payments/collect/', CollectPayView.as_view(), name='payment-orders-collect'),
    path('v1/payments/status/', CheckOrderStatusView.as_view(), name='payment-orders-status'),
    path("v1/payments/verify/", VerifyPaymentView.as_view(), name="payment-verify"),
    path("v1/refunds/initiate/", InitiateRefundView.as_view(), name="refund-initiate"),

    # Dashboard
    path("api/payin/dashboard", DashboardView.as_view(), name="payin-dashboard"),
    path("api/payin/payments/", PaymentsDashboardView.as_view(), name="payin-payments"),
    path("api/payin/dashboard2", DashboardV2View.as_view(), name="payin-dashboard2"),
    path("api/payin/refunds/", RefundDashboardView.as_view(), name="refund-dashboard"),
    path("api/dashboard/", MainDashboardView.as_view(), name="main-dashboard"),

    # Password reset
    path('forgot-password/', ForgotPasswordView.as_view()),
    path('reset-password/', ResetPasswordView.as_view()),

    # KYC numbers
    path("kyc/pan/verify/", VerifyPANView.as_view(), name="kyc-pan-verify"),
    path("kyc/gst/verify/", VerifyGSTView.as_view(), name="kyc-gst-verify"),
    path("kyc/gst/signatory/", GSTSignatoryView.as_view(), name="kyc-gst-signatory"),

    # KYC images
    path("kyc/pan/image-verify/", PanImageVerifyView.as_view()),
    path("kyc/gst/image-verify/", GstImageVerifyView.as_view()),

    # Encryption & webhook
    path("kyc/test-encrypted-key/", TestEncryptKeyView.as_view()),
    path("webhook/", WebhookAPIView.as_view()),

]
