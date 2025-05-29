from django.contrib import admin
from django.urls import path
from .views import MerchantOnboardingView, CreatePaymentView, PaymentStatusView, AdminMerchantPaymentListView

urlpatterns = [
    path('merchant/', MerchantOnboardingView.as_view(), name='merchant'),
    path('create-payment/', CreatePaymentView.as_view(), name="payment"),
    path('payment-status/<str:order_id>/', PaymentStatusView.as_view(), name="payment-status"),
    path('admin/merchants/', AdminMerchantPaymentListView.as_view(), name='admin-merchant-payments'),
]