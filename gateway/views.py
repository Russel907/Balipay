from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Merchant, Payment
from .serializers import MerchantSerializer, PaymentSerializer, MerchantWithPaymentsSerializer
from django.shortcuts import get_object_or_404



class MerchantOnboardingView(APIView):
    def post(self, request):
        serializer = MerchantSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        merchants = Merchant.objects.all()
        serializer = MerchantSerializer(merchants, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class CreatePaymentView(APIView):
    def post(self, request):
        api_key = request.headers.get('API-Key')
        if not api_key:
            return Response({'error': 'API Key missing'}, status=status.HTTP_401_UNAUTHORIZED)
        merchant = get_object_or_404(Merchant, api_key=api_key)

        order_id = request.data.get('order_id')
        amount = request.data.get('amount')

        if not order_id or not amount:
            return Response({'error': 'Missing fields'}, status=status.HTTP_400_BAD_REQUEST)

        payment = Payment.objects.create(
            merchant=merchant,
            order_id=order_id,
            amount=amount,
            status='pending'
        )

        upi_link = f"upi://pay?pa={merchant.upi_id}&pn={merchant.business_name}&am={amount}&tn={order_id}"
        return Response({'upi_link': upi_link}, status=status.HTTP_201_CREATED)


class PaymentStatusView(APIView):
    def get(self, request, order_id):
        api_key = request.headers.get('API-Key')
        if not api_key:
            return Response({'error': 'API Key missing'}, status=status.HTTP_401_UNAUTHORIZED)

        merchant = get_object_or_404(Merchant, api_key=api_key)

        payment = get_object_or_404(Payment, order_id=order_id, merchant=merchant)

        return Response({
            "order_id": payment.order_id,
            "amount": str(payment.amount),
            "status": payment.status,
            "timestamp": payment.created_at.isoformat()
        })



class AdminMerchantPaymentListView(APIView):
    def get(self, request):
        merchants = Merchant.objects.prefetch_related('payment_set').all()
        serializer = MerchantWithPaymentsSerializer(merchants, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)