from django.urls import path
from .views import MerchantSignupView, MerchantLoginView, CreatePaymentView, SendOTPView, ValidateOTPView,  APIKeyListView
from .views import GenerateTestAPIKeyView, RevokeAPIKeyView, ListPaymentOrdersView, CancelPaymentOrderView, CreateDeepLinkView
from .views import CollectPayView, CheckOrderStatusView, DashboardView, DashboardV2View, PaymentsDashboardView, OrdersDashboardView
# from .views import DisputesDashboardView
from .views import CreateRefundView, RefundsDashboardView, SummaryReportView, GenerateLiveAPIKeyView

urlpatterns = [
    path('signup/merchant/', MerchantSignupView.as_view(), name='merchant-signup'),
    path('merchant/login/', MerchantLoginView.as_view(), name='merchant-login'),

    path("otp/send/", SendOTPView.as_view(), name="otp-send"),
    path("otp/verify/", ValidateOTPView.as_view(), name="otp-verify"),

    path("keys/generate/test/", GenerateTestAPIKeyView.as_view(), name="generate-test-key"),
    path("keys/generate/live/", GenerateLiveAPIKeyView.as_view(), name="generate-live-key"),
    path("api-keys/", APIKeyListView.as_view(), name="list_api_keys"),
    path("api-keys/<str:key_id>/revoke/", RevokeAPIKeyView.as_view(), name="revoke_api_key"),
    
    path('v1/payments/create/', CreatePaymentView.as_view(), name='payment-create'),
    path('v1/payments/orders/', ListPaymentOrdersView.as_view(), name='payment-orders-list'),
    path('v1/payments/cancel/', CancelPaymentOrderView.as_view(), name='payment-orders-cancel'),
    path('v1/payments/deeplink/', CreateDeepLinkView.as_view(), name='payment-orders-deeplink'),
    path('v1/payments/collect/', CollectPayView.as_view(), name='payment-orders-collect'),
    path('v1/payments/status/',CheckOrderStatusView.as_view(), name='payment-orders-status'),
    path('v1/payments/refund/', CreateRefundView.as_view(), name="create-refund"),

    path("payin/dashboard", DashboardView.as_view(), name="payin-dashboard"),
    path("payin/dashboard2", DashboardV2View.as_view(), name="payin-dashboard2"),
    path("payin/dashboard/payments/", PaymentsDashboardView.as_view()),
    path("payin/dashboard/refunds/", RefundsDashboardView.as_view()),
    path("payin/dashboard/orders/", OrdersDashboardView.as_view()),
    # path("payin/dashboard/disputes/", DisputesDashboardView.as_view())
    path("payin/dashboard/summary/", SummaryReportView.as_view())

]
