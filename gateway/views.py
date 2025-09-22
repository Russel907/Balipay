from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Merchant, Payment
from .serializers import MerchantSerializer, PaymentSerializer, MerchantWithPaymentsSerializer, MerchantLoginSerializer
from django.shortcuts import get_object_or_404
from django.db import transaction
from decimal import Decimal, InvalidOperation
import urllib.parse, qrcode, io, base64

class MerchantOnboardingView(APIView):
    def post(self, request):
        serializer = MerchantSerializer(data=request.data)
        if serializer.is_valid():
            merchant = serializer.save()
            response_data =  MerchantSerializer(merchant).data
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        merchants = Merchant.objects.all()
        serializer = MerchantSerializer(merchants, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class MerchantLoginView(APIView):
    def post(self, request):
        serializer = MerchantLoginSerializer(data=request.data)
        if serializer.is_valid():
            merchant = serializer.validated_data["merchant"]
            response_data = MerchantSerializer(merchant).data
            return Response(response_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CreatePaymentView(APIView):

    def post(self, request):
        api_key = request.headers.get('API-Key')
        if not api_key:
            return Response({'error': 'API Key missing'}, status=status.HTTP_401_UNAUTHORIZED)
        merchant = get_object_or_404(Merchant, api_key=api_key)

        order_id = request.data.get('order_id')
        amount = request.data.get('amount')
        vpa = request.data.get('vpa')          # <-- will be used as pa=
        note = request.data.get('note', '')

        if not order_id or not amount or not vpa:
            return Response({'error': 'order_id, amount and vpa are required'}, status=status.HTTP_400_BAD_REQUEST)

        # normalize/validate amount
        try:
            amount_str = f"{Decimal(amount):.2f}"
        except (InvalidOperation, TypeError):
            return Response({'error': 'amount must be a number'}, status=status.HTTP_400_BAD_REQUEST)

        # idempotent create
        with transaction.atomic():
            payment, created = Payment.objects.get_or_create(
                merchant=merchant,
                order_id=order_id,
                defaults={"amount": amount_str, "vpa": vpa, "status": "pending"},
            )
            if not created and str(payment.amount) != amount_str:
                return Response(
                    {
                        "error": "Duplicate order_id with mismatched amount",
                        "existing_amount": str(payment.amount),
                        "posted_amount": amount_str,
                    },
                    status=status.HTTP_409_CONFLICT,
                )

        # build UPI deeplink (pa=<vpa>)
        params = {
            "pa": vpa,                                # <-- your VPA here
            "pn": merchant.business_name[:40],
            "am": amount_str,
            "tr": payment.order_id,                   # transaction/order reference
            "tn": (note or f"Order {payment.order_id}")[:40],
            "cu": "INR",
        }
        upi_link = "upi://pay?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)

        # make QR as base64 PNG
        img = qrcode.make(upi_link)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_image_base64 = base64.b64encode(buf.getvalue()).decode("ascii")

        return Response(
            {
                "created": created,
                "payment": PaymentSerializer(payment).data,
                "upi_link": upi_link,
                "qr_image_base64": qr_image_base64,
            },
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def get(self, request):
        api_key = request.headers.get('API-Key')
        if not api_key:
            return Response({'error': 'API Key missing'}, status=status.HTTP_401_UNAUTHORIZED)
        merchant = get_object_or_404(Merchant, api_key=api_key)

        payment = get_object_or_404(Payment, merchant=merchant, order_id=order_id)

        return Response({
            'order_id': payment.order_id,
            'amount': payment.amount,
            'status': payment.status,
            'vpa': payment.vpa,
            'created_at': payment.created_at,
        }, status=status.HTTP_200_OK)

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