from django.urls import path
from .views import MerchantSignupView, MerchantLoginView, CreatePaymentView, SendOTPView, ValidateOTPView,  APIKeyListView
from .views import GenerateAPIKeyView, RevokeAPIKeyView, ListPaymentOrdersView, CancelPaymentOrderView, CreateDeepLinkView, CreateQRCodeView
from .views import CollectPayView, CheckOrderStatusView, DashboardView, DashboardV2View, RefundDashboardView, MainDashboardView




urlpatterns = [
    path('signup/merchant/', MerchantSignupView.as_view(), name='merchant-signup'),
    path('merchant/login/', MerchantLoginView.as_view(), name='merchant-login'),

    path("otp/send/", SendOTPView.as_view(), name="otp-send"),
    path("otp/verify/", ValidateOTPView.as_view(), name="otp-verify"),

    path("api-keys/generate/", GenerateAPIKeyView.as_view(), name="generate_api_key"),
    path("api-keys/", APIKeyListView.as_view(), name="list_api_keys"),
    path("api-keys/<str:key_id>/revoke/", RevokeAPIKeyView.as_view(), name="revoke_api_key"),
    
    path('v1/payments/create/', CreatePaymentView.as_view(), name='payment-create'),
    path('v1/payments/orders/', ListPaymentOrdersView.as_view(), name='payment-orders-list'),
    path('v1/payments/cancel/', CancelPaymentOrderView.as_view(), name='payment-orders-cancel'),
    path('v1/payments/deeplink/', CreateDeepLinkView.as_view(), name='payment-orders-deeplink'),
    path('v1/payments/qrcode/', CreateQRCodeView.as_view(), name="payment-qrcode"),
    path('v1/payments/collect/', CollectPayView.as_view(), name='payment-orders-collect'),
    path('v1/payments/status/',CheckOrderStatusView.as_view(), name='payment-orders-status'),

    path("api/payin/dashboard", DashboardView.as_view(), name="payin-dashboard"),
    path("api/payin/dashboard2", DashboardV2View.as_view(), name="payin-dashboard2"),
    path("api/payin/refunds/", RefundDashboardView.as_view(), name="refund-dashboard"),
    path("api/dashboard/", MainDashboardView.as_view(), name="main-dashboard"),



]
