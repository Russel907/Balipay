from django.contrib import admin
from django.urls import path
from .views import MerchantOnboardingView, CreatePaymentView, PaymentStatusView, AdminMerchantPaymentListView, MerchantLoginView

urlpatterns = [
    path('merchant/', MerchantOnboardingView.as_view(), name='merchant'),
    path('login/', MerchantLoginView.as_view(), name='merchant-login'),
    path('v1/payments/create/', CreatePaymentView.as_view(), name="payment"),
    path('payment-status/<str:order_id>/', PaymentStatusView.as_view(), name="payment-status"),
    path('admin/merchants/', AdminMerchantPaymentListView.as_view(), name='admin-merchant-payments'),
]