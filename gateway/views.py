
import razorpay 
import logging
import requests
import urllib.parse, qrcode, io, base64, hmac, hashlib, json, time

from django.shortcuts import get_object_or_404
from django.db import transaction
from django.core.cache import cache
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.contrib.auth.hashers import check_password
from django.conf import settings
from django.db.models import Q, Count, Sum, Value as V, DecimalField
from django.db.models.functions import Coalesce, TruncMonth


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from rest_framework.authtoken.models import Token
from rest_framework import serializers

from decimal import Decimal, InvalidOperation
from .utils import send_otp_via_messagecentral
from datetime import timedelta, date, datetime
from urllib.parse import urlencode
from .utils import _get_auth_token, MESSAGECENTRAL_BASE 

from .models import Merchant, Payment, OTP, APIKey
from .serializers import MerchantSignupSerializer, MerchantLoginSerializer, SendOTPSerializer, VerifyOTPSerializer, GenerateAPIKeySerializer, APIKeyListSerializer, PaymentSerializer 
from .razorpay_client import create_razorpay_order

logger = logging.getLogger(__name__)
WEBHOOK_TOLERANCE_SECONDS = 5 * 60
REPLAY_CACHE_PREFIX = "wh_sig_"
REPLAY_CACHE_TTL = 10 * 60

RESEND_COOLDOWN_SECONDS = getattr(settings, "RESEND_COOLDOWN_SECONDS", 60)
OTP_TTL_SECONDS = getattr(settings, "OTP_TTL_SECONDS", 5 * 60)
MAX_OTP_ATTEMPTS = getattr(settings, "MAX_OTP_ATTEMPTS", 5)

client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))



class MerchantSignupView(generics.CreateAPIView):
    serializer_class = MerchantSignupSerializer
    queryset = Merchant.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        merchant = serializer.save()
        return Response(
            {
                "merchant_id": merchant.id,
                "message": "Merchant profile created.",
                "token": merchant.token, 
            },
            status=status.HTTP_201_CREATED
        )


class MerchantLoginView(APIView):
    def post(self, request):
        serializer = MerchantLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            merchant = serializer.validated_data['merchant']
            token, _ = Token.objects.get_or_create(user=user)
            token_key = token.key
            data = {
                "id": merchant.id,
                "business_name": merchant.business_name,
                "contact_name": merchant.contact_name,
                "token": token_key,
            }
            return Response(data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)






        merchant =  merchant = getattr(request.user, "merchant_profile", None)
        if not merchant:
            return Response(
                {"detail": "Merchant profile not found for this user."},
                status=status.HTTP_404_NOT_FOUND,
            )
        phone_number = merchant.phone_number
        if not phone_number:
            return Response(
                {"detail": "No phone number found for this merchant."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        last_otp = merchant.merchant_profile.order_by("-created_at").first()
        if last_otp and (timezone.now() - last_otp.created_at).total_seconds() < RESEND_COOLDOWN_SECONDS:
            retry_after = RESEND_COOLDOWN_SECONDS - int((timezone.now() - last_otp.created_at).total_seconds())
            return Response(
                {"detail": "Please wait before requesting another OTP.", "retry_after_seconds": retry_after},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        # create OTP
        otp_obj = OTP.create_otp(merchant, ttl_seconds=OTP_TTL_SECONDS)

        # send SMS
        sms_text = f"Your verification code is {otp_obj.code}. It will expire in {OTP_TTL_SECONDS//60} minutes."
        ok = send_sms(merchant.phone_number, sms_text)
        if not ok:
            # you can delete otp_obj or keep it and allow resend
            return Response({"detail": "Failed to send OTP. Try again later."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({
            "otp_id": otp_obj.id,
            "expires_at": otp_obj.expires_at,
            "message": "OTP sent to registered mobile number."
        }, status=status.HTTP_201_CREATED)


class SendOTPView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = SendOTPSerializer

    def post(self, request, *args, **kwargs):
        merchant = getattr(request.user, "merchant_profile", None)
        if not merchant:
            return Response({"detail": "Merchant profile not found."}, status=status.HTTP_404_NOT_FOUND)

        phone_number = merchant.phone_number
        if not phone_number:
            return Response({"detail": "No phone number found."}, status=status.HTTP_400_BAD_REQUEST)

        # throttle check
        last_otp = merchant.otps.order_by("-created_at").first() if hasattr(merchant, "otps") else None
        if last_otp and (timezone.now() - last_otp.created_at).total_seconds() < RESEND_COOLDOWN_SECONDS:
            retry_after = RESEND_COOLDOWN_SECONDS - int((timezone.now() - last_otp.created_at).total_seconds())
            return Response({"detail":"Please wait before requesting another OTP.","retry_after_seconds": retry_after},
                            status=status.HTTP_429_TOO_MANY_REQUESTS)

        with transaction.atomic():
            otp_obj = OTP.create_otp(merchant, ttl_seconds=OTP_TTL_SECONDS)
            sms_text = f"Your verification code is {otp_obj.code}. It will expire in {OTP_TTL_SECONDS // 60} minutes."

            ok, provider_resp = send_otp_via_messagecentral(phone_number, sms_text)
            logger.debug("MessageCentral send response: %s", provider_resp)

            if not ok:
                logger.error("Failed to send OTP to %s: %s", phone_number, provider_resp)
                otp_obj.delete()
                return Response({"detail": "Failed to send OTP. Try again later."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

            # extract provider IDs if available and persist
            data = provider_resp.get("data") if isinstance(provider_resp, dict) else None
            if data:
                verification_id = data.get("verificationId")
                transaction_id = data.get("transactionId")
                if verification_id:
                    otp_obj.provider_verification_id = str(verification_id)
                if transaction_id:
                    otp_obj.provider_transaction_id = str(transaction_id)
                otp_obj.save()

            logger.info("OTP sent successfully to %s (merchant_id=%s, otp_id=%s)", phone_number, merchant.id, otp_obj.id)

            return Response({
                "otp_id": otp_obj.id,
                "expires_at": otp_obj.expires_at,
                "message": f"OTP sent to {phone_number}",
                "provider": {"verificationId": otp_obj.provider_verification_id, "transactionId": otp_obj.provider_transaction_id}
            }, status=status.HTTP_201_CREATED)


class ValidateOTPSerializer(serializers.Serializer):
    otp_id = serializers.IntegerField(required=False)
    verification_id = serializers.CharField(required=False, allow_blank=True)
    code = serializers.CharField(max_length=10)


class ValidateOTPView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ValidateOTPSerializer

    def get_otp_obj(self, validated_data, user):
        otp_id = validated_data.get("otp_id")
        verification_id = validated_data.get("verification_id")
        merchant = getattr(user, "merchant_profile", None)
        if not merchant:
            return None, Response({"detail": "Merchant profile not found."}, status=status.HTTP_404_NOT_FOUND)

        if otp_id:
            try:
                otp_obj = OTP.objects.get(id=otp_id, merchant=merchant)
            except OTP.DoesNotExist:
                return None, Response({"detail":"OTP not found."}, status=status.HTTP_404_NOT_FOUND)
        elif verification_id:
            try:
                otp_obj = OTP.objects.get(provider_verification_id=verification_id, merchant=merchant)
            except OTP.DoesNotExist:
                return None, Response({"detail":"OTP not found for given verification id."}, status=status.HTTP_404_NOT_FOUND)
        else:
            # fallback: latest OTP for merchant
            otp_obj = merchant.otps.order_by("-created_at").first()
            if not otp_obj:
                return None, Response({"detail":"No OTP found for this merchant."}, status=status.HTTP_404_NOT_FOUND)
        return otp_obj, None

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data
        code = validated["code"]
        otp_obj, error_response = self.get_otp_obj(validated, request.user)
        if error_response:
            return error_response

        # check expiry/consumed
        if otp_obj.consumed:
            return Response({"detail":"OTP already used."}, status=status.HTTP_400_BAD_REQUEST)
        if otp_obj.is_expired():
            return Response({"detail":"OTP expired."}, status=status.HTTP_400_BAD_REQUEST)

        # check attempts
        if otp_obj.attempts >= MAX_OTP_ATTEMPTS:
            return Response({"detail":"Maximum attempts exceeded."}, status=status.HTTP_403_FORBIDDEN)

        # build validate URL
        country = getattr(settings, "MESSAGECENTRAL_COUNTRY_CODE", "91")
        customer_id = getattr(settings, "MESSAGECENTRAL_CUSTOMER_ID")
        verification_id = otp_obj.provider_verification_id
        if not verification_id:
            return Response({"detail": "Provider verification id missing. Cannot validate with provider."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        params = {
            "countryCode": country,
            "mobileNumber": otp_obj.merchant.phone_number,
            "verificationId": verification_id,
            "customerId": customer_id,
            "code": code
        }
        base = getattr(settings, "MESSAGECENTRAL_BASE", "https://cpaas.messagecentral.com")
        validate_url = f"{base}/verification/v3/validateOtp?{urlencode(params)}"

        # get auth token
        ok, token_or_err = _get_auth_token(country=country)
        if not ok:
            return Response({"detail": "Failed to obtain auth token", "error": token_or_err}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        headers = {"authToken": token_or_err, "Accept": "application/json"}

        try:
            resp = requests.get(validate_url, headers=headers, timeout=10)
        except requests.RequestException as exc:
            logger.exception("Network error while validating OTP")
            return Response({"detail":"Network error validating OTP."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # parse provider response
        try:
            j = resp.json()
        except ValueError:
            j = {"raw": resp.text}

        # Always increment attempts and save
        otp_obj.attempts = otp_obj.attempts + 1
        otp_obj.save()

        if resp.status_code == 200 and j.get("message") == "SUCCESS":
            with transaction.atomic():
                otp_obj.consumed = True
                otp_obj.save()
                m = otp_obj.merchant
                m.is_active = True
                m.save(update_fields=["is_active"])
            return Response({"detail":"OTP verified", "provider": j}, status=status.HTTP_200_OK)
        else:
            # handle failed validation
            error_msg = j.get("message") or j.get("errorMessage") or j
            return Response({"detail":"OTP verification failed","provider": error_msg, "attempts": otp_obj.attempts},
                            status=status.HTTP_400_BAD_REQUEST)


class IsMerchantAuthenticated(permissions.IsAuthenticated):
    pass


class GenerateAPIKeyView(generics.GenericAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = GenerateAPIKeySerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        merchant = getattr(request.user, "merchant_profile", None)
        if not merchant:
            return Response({"detail": "Merchant profile not found."}, status=status.HTTP_404_NOT_FOUND)

        if not getattr(merchant, "is_active", False):
            return Response({"detail": "Merchant phone number not verified. Cannot generate API keys."},
                            status=status.HTTP_403_FORBIDDEN)

        name = serializer.validated_data.get("name")
        mode = serializer.validated_data.get("mode", "test")
        ttl_seconds = serializer.validated_data.get("ttl_seconds", None)

        with transaction.atomic():
            api_key_obj, raw_secret = APIKey.create_key(merchant=merchant, name=name, mode=mode, ttl_seconds=ttl_seconds)

        return Response({
            "key_id": api_key_obj.key_id,
            "secret": raw_secret,            
            "created_at": api_key_obj.created_at,
            "expires_at": api_key_obj.expires_at,
            "mode": api_key_obj.mode,
            "message": "Save the secret now — it will be shown only once."
        }, status=status.HTTP_201_CREATED)


class APIKeyListView(generics.ListAPIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = APIKeyListSerializer

    def get_queryset(self):
        merchant = getattr(self.request.user, "merchant_profile", None)
        if not merchant:
            return APIKey.objects.none()
        return APIKey.objects.filter(merchant=merchant).order_by("-created_at")


class RevokeAPIKeyView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "key_id"
    queryset = APIKey.objects.all()

    def delete(self, request, *args, **kwargs):
        merchant = getattr(request.user, "merchant_profile", None)
        if not merchant:
            return Response({"detail": "Merchant profile not found."}, status=status.HTTP_404_NOT_FOUND)

        key_id = kwargs.get("key_id")
        try:
            api_key = APIKey.objects.get(key_id=key_id, merchant=merchant)
        except APIKey.DoesNotExist:
            return Response({"detail": "API key not found."}, status=status.HTTP_404_NOT_FOUND)

        api_key.revoked = True
        api_key.save(update_fields=["revoked"])
        return Response({"detail": "API key revoked."}, status=status.HTTP_200_OK)


def _authenticate_api_client(client_id: str, secret_key: str):
    try:
        api_key = APIKey.objects.select_related("merchant").get(key_id=client_id, revoked=False)
    except APIKey.DoesNotExist:
        return None, None

    # check secret using Django's password hash
    if not check_password(secret_key, api_key.hashed_secret):
        return None, None

    # check expiry
    if api_key.expires_at and timezone.now() > api_key.expires_at:
        return None, None

    # update last_used_at for auditing
    api_key.last_used_at = timezone.now()
    api_key.save(update_fields=["last_used_at"])

    return api_key, api_key.merchant


class CreatePaymentView(APIView):
    def post(self, request):
        d = request.data
        client_id = d.get('clientId')
        secret_key = d.get('secretKey')
        client_order_id = d.get('clientOrderId')
        amount = d.get('amount')
        name = d.get('name')
        mobile = d.get('mobileNo')
        email = d.get('emailID')
        vpa = d.get('vpa')

        # required check
        if not all([client_id, secret_key, client_order_id, amount, name, mobile, email]):
            return Response({"Statuscode": 0, "Message": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)

        # authenticate API client
        api_key, merchant = _authenticate_api_client(client_id, secret_key)
        if not api_key or not merchant:
            return Response({"Statuscode": 0, "Message": "Invalid API credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        # normalize and validate amount
        try:
            amount_dec = Decimal(str(amount))
            if amount_dec <= 0:
                return Response({"Statuscode": 0, "Message": "amount must be > 0"}, status=status.HTTP_400_BAD_REQUEST)
            amount_str = f"{amount_dec:.2f}"
            amount_in_paise = int((amount_dec * 100).to_integral_value())
            if amount_in_paise <= 0:
                return Response({"Statuscode": 0, "Message": "amount must be at least 0.01"}, status=status.HTTP_400_BAD_REQUEST)
        except (InvalidOperation, TypeError):
            return Response({"Statuscode": 0, "Message": "amount must be numeric"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            with transaction.atomic():
                payment, created = Payment.objects.select_for_update().get_or_create(
                    merchant=merchant,
                    order_id=client_order_id,
                    defaults={
                        "amount": amount_str,
                        "vpa": vpa or getattr(merchant, "upi_id", "") or "",
                        "status": "pending",
                        "payer_name": name,
                        "payer_mobile": mobile,
                        "payer_email": email,
                    }
                )

                # if existing payment has different amount -> conflict
                if not created and str(payment.amount) != amount_str:
                    return Response({
                        "Statuscode": 0,
                        "Message": "Duplicate clientOrderId with mismatched amount",
                        "orderId": payment.order_id,
                        "currency": getattr(payment, "currency", "INR"),
                        "amount": str(payment.amount),
                        "clientOrderId": client_order_id
                    }, status=status.HTTP_409_CONFLICT)

                # If provider order was already created for this payment, reuse it (idempotency)
                razorpay_order_response = None
                if getattr(payment, "provider_order_id", None):
                    razorpay_order_id = payment.provider_order_id
                    razorpay_order_response = {
                        "id": razorpay_order_id,
                        "note": "reused existing provider order",
                    }
                else:
                    # create provider order using PLATFORM credentials (do NOT use merchant-supplied razorpay creds)
                    auth = (settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET)
                    idempotency_key = f"platform:{merchant.id}:{client_order_id}"

                    notes = {
                        "merchant_id": str(merchant.id),
                        "client_order_id": client_order_id
                    }

                    # call helper that tries SDK then HTTP (and sets Idempotency-Key)
                    razorpay_order_response = create_razorpay_order(
                        auth=auth,
                        amount_in_paise=amount_in_paise,
                        receipt=client_order_id,
                        notes=notes,
                        idempotency_key=idempotency_key
                    )

                    razorpay_order_id = razorpay_order_response.get("id")
                    if razorpay_order_id:
                        # persist provider order info onto Payment (preferred fields)
                        # set provider_order_id and other helpful fields
                        payment.provider_order_id = razorpay_order_id
                        # store raw response if JSONField exists
                        try:
                            payment.provider_order_response = razorpay_order_response
                        except Exception:
                            # if JSONField not present, ignore
                            logger.debug("provider_order_response field not available on Payment model")
                        # cache numeric paise and currency
                        try:
                            payment.amount_in_paise = amount_in_paise
                            payment.currency = "INR"
                        except Exception:
                            logger.debug("amount_in_paise/currency fields not available on Payment model")
                        # store idempotency key for debugging
                        try:
                            payment.idempotency_key = idempotency_key
                        except Exception:
                            logger.debug("idempotency_key field not available on Payment model")

                        # keep backward-compatible provider_txn_id if present
                        if hasattr(payment, "provider_txn_id"):
                            payment.provider_txn_id = razorpay_order_id

                        # Save all available fields in one go (collect fields that exist)
                        update_fields = ["provider_order_id", "updated_at"]
                        if hasattr(payment, "provider_order_response"):
                            update_fields.append("provider_order_response")
                        if hasattr(payment, "amount_in_paise"):
                            update_fields.append("amount_in_paise")
                        if hasattr(payment, "currency"):
                            update_fields.append("currency")
                        if hasattr(payment, "idempotency_key"):
                            update_fields.append("idempotency_key")
                        if hasattr(payment, "provider_txn_id"):
                            update_fields.append("provider_txn_id")

                        payment.save(update_fields=list(dict.fromkeys(update_fields)))

        except Exception as exc:
            logger.exception("CreatePaymentView failed while creating payment/provider order: %s", exc)
            return Response({"Statuscode": 0, "Message": "Failed to create provider order"}, status=status.HTTP_502_BAD_GATEWAY)

        # Build response (include provider block)
        provider_block = {
            "provider_name": "razorpay",
            "order_id": getattr(payment, "provider_order_id", None) or getattr(payment, "provider_txn_id", None),
            "order_response": None
        }
        # Prefer stored JSONField; else use local response variable
        if hasattr(payment, "provider_order_response") and payment.provider_order_response:
            provider_block["order_response"] = payment.provider_order_response
        else:
            provider_block["order_response"] = razorpay_order_response

        response = {
            "Statuscode": 1,
            "Message": "Order Generated" if created else "Order Retrieved",
            "orderId": payment.order_id,
            "currency": getattr(payment, "currency", "INR"),
            "amount": amount_str,
            "clientOrderId": client_order_id,
            # "provider": provider_block
        }
        return Response(response, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)


class ListPaymentOrdersView(APIView):

    def get(self, request):
        client_id = request.query_params.get("clientId")
        secret_key = request.query_params.get("secretKey")

        # validate
        if not client_id or not secret_key:
            return Response({"Statuscode": 0, "Message": "Missing credentials"},
                            status=status.HTTP_400_BAD_REQUEST)

        # authenticate
        api_key, merchant = _authenticate_api_client(client_id, secret_key)
        if not api_key or not merchant:
            return Response({"Statuscode": 0, "Message": "Invalid API credentials"},
                            status=status.HTTP_401_UNAUTHORIZED)

        # optional filters
        client_order_id = request.query_params.get("clientOrderId")
        status_filter = request.query_params.get("status")       # pending, success, failed
        start_date = request.query_params.get("startDate")       # yyyy-mm-dd
        end_date = request.query_params.get("endDate")

        qs = Payment.objects.filter(merchant=merchant).order_by("-created_at")

        if client_order_id:
            qs = qs.filter(order_id=client_order_id)

        if status_filter:
            qs = qs.filter(status=status_filter)

        if start_date:
            qs = qs.filter(created_at__date__gte=start_date)

        if end_date:
            qs = qs.filter(created_at__date__lte=end_date)

        # prepare list
        data = []
        for p in qs.only(
            "order_id", "amount", "status", "created_at",
            "provider_order_id", "payer_name", "payer_mobile"
        ):
            data.append({
                "orderId": p.order_id,
                "amount": str(p.amount),
                "status": p.status,
                "currency": getattr(p, "currency", "INR"),
                "providerOrderId": getattr(p, "provider_order_id", None),
                "payerName": p.payer_name,
                "payerMobile": p.payer_mobile,
                "createdAt": p.created_at.isoformat()
            })

        return Response({
            "Statuscode": 1,
            "Message": "Payment Orders List",
            "count": len(data),
            "orders": data
        }, status=status.HTTP_200_OK)


class CancelPaymentOrderView(APIView):

    def post(self, request):
        d = request.data
        
        client_id = d.get("clientId")
        secret_key = d.get("secretKey")
        order_id = d.get("OrderId")
        reason = d.get("reason")

        missing = []

        if not client_id:
            missing.append("clientId")
        if not secret_key:
            missing.append("secretKey")
        if not order_id:
            missing.append("orderId")
        if not reason:
            missing.append("reason")

        if missing:
            return Response({
                "statusCode": 0,
                "message": f"Missing required fields: {', '.join(missing)}",
                "missingFields": missing
            }, status=status.HTTP_400_BAD_REQUEST)
        # Authenticate API Key
        api_key, merchant = _authenticate_api_client(client_id, secret_key)
        if not api_key or not merchant:
            return Response({
                "statusCode": 0,
                "message": "Invalid API credentials"
            }, status=status.HTTP_401_UNAUTHORIZED)

        try:
            payment = Payment.objects.get(merchant=merchant, order_id=order_id)
        except Payment.DoesNotExist:
            return Response({
                "statusCode": 6,
                "message": "Order not found",
                "orderId": order_id
            }, status=status.HTTP_404_NOT_FOUND)

        # If already completed, cannot cancel
        if payment.status in ["success", "completed"]:
            return Response({
                "statusCode": 0,
                "message": "Order is already completed. Cannot cancel.",
                "orderId": order_id
            }, status=status.HTTP_400_BAD_REQUEST)

        # If already cancelled, return same
        if payment.status == "cancelled":
            return Response({
                "statusCode": 1,
                "message": "Order already cancelled",
                "orderId": order_id
            }, status=status.HTTP_200_OK)

        # Cancel the order
        payment.status = "cancelled"
        payment.cancel_reason = reason if hasattr(payment, "cancel_reason") else ""
        payment.save(update_fields=["status"])

        return Response({
            "statusCode": 1,
            "message": "Order cancelled successfully",
            "orderId": order_id
        }, status=status.HTTP_200_OK)


class CreateDeepLinkView(APIView):

    def post(self, request):
        d = request.data

        client_id = d.get("clientId")
        secret_key = d.get("secretKey")
        note = d.get("note")
        order_id = d.get("OrderId")

        # ✅ Identify missing fields
        missing = []
        if not client_id:
            missing.append("clientId")
        if not secret_key:
            missing.append("secretKey")
        if not note:
            missing.append("note")
        if not order_id:
            missing.append("orderId")

        if missing:
            return Response({
                "statusCode": 0,
                "message": f"Missing required fields: {', '.join(missing)}",
                "missingFields": missing
            }, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Authenticate API Client
        api_key, merchant = _authenticate_api_client(client_id, secret_key)
        if not api_key or not merchant:
            return Response({
                "statusCode": 0,
                "message": "Invalid API credentials"
            }, status=status.HTTP_401_UNAUTHORIZED)

        # ✅ Check if payment order exists
        try:
            payment = Payment.objects.get(merchant=merchant, order_id=order_id)
        except Payment.DoesNotExist:
            return Response({
                "statusCode": 0,
                "message": "Order not found",
                "orderId": order_id
            }, status=status.HTTP_404_NOT_FOUND)

        # ✅ Fail if provider order not created (create payment first)
        if not payment.provider_order_id:
            return Response({
                "statusCode": 0,
                "message": "Provider order not created yet. Create payment first.",
                "orderId": order_id
            }, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Amount for UPI
        amount = payment.amount
        vpa = payment.vpa or getattr(merchant, "upi_id", "")

        if not vpa:
            return Response({
                "statusCode": 0,
                "message": "VPA / UPI ID not configured",
                "orderId": order_id
            }, status=status.HTTP_400_BAD_REQUEST)
        if payment.status in ["cancelled", "failed", "paid", "completed"]:
            return Response({
                "statusCode": 0,
                "message": f"Cannot generate deeplink for a {payment.status} order",
                "orderId": order_id
            }, status=status.HTTP_400_BAD_REQUEST)

        payer_display_name = merchant.business_name or merchant.contact_name
        upi_url = (
            f"upi://pay?"
            f"pa={vpa}"
            f"&pn={payer_display_name}"
            f"&am={amount}"
            f"&cu=INR"
            f"&tn={note}"
            f"&tr={payment.provider_order_id}"
        )

        # ✅ Save deeplink if model has the field (optional)
        if hasattr(payment, "upi_link"):
            payment.upi_link = upi_url
            payment.save(update_fields=["upi_link"])

        # ✅ Response
        return Response({
            "statusCode": 1,
            "Message": "Deeplink Generated Successfully",
            "OrderId": order_id,
            "Upiurl": upi_url
        }, status=status.HTTP_200_OK)


class CollectPayView(APIView):

    def post(self, request):
        d = request.data

        client_id = d.get("clientId")
        secret_key = d.get("secretKey")
        customer_vpa = d.get("vpa")
        order_id = d.get("OrderId")

        # ✅ Required fields validation (detailed)
        missing = []
        if not client_id: missing.append("clientId")
        if not secret_key: missing.append("secretKey")
        if not customer_vpa: missing.append("vpa")
        if not order_id: missing.append("orderId")

        if missing:
            return Response({
                "statusCode": 0,
                "message": f"Missing required fields: {', '.join(missing)}",
                "missingFields": missing
            }, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Authenticate API credentials
        api_key, merchant = _authenticate_api_client(client_id, secret_key)
        if not api_key or not merchant:
            return Response({
                "statusCode": 0,
                "message": "Invalid API credentials"
            }, status=status.HTTP_401_UNAUTHORIZED)

        # ✅ Check payment exists
        try:
            payment = Payment.objects.get(merchant=merchant, order_id=order_id)
        except Payment.DoesNotExist:
            return Response({
                "statusCode": 0,
                "message": "Order not found",
                "orderId": order_id
            }, status=status.HTTP_404_NOT_FOUND)

        # ✅ Cannot collect pay for cancelled/paid orders
        if payment.status in ["cancelled", "failed", "paid"]:
            return Response({
                "statusCode": 0,
                "message": f"Cannot initiate collect request for a {payment.status} order",
                "orderId": order_id
            }, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Required fields for collect pay
        amount = str(payment.amount)
        merchant_vpa = payment.vpa or getattr(merchant, "phone_number", None)
        merchant_name = merchant.business_name or merchant.contact_name

        if not merchant_vpa:
            return Response({
                "statusCode": 0,
                "message": "Merchant VPA not configured",
                "orderId": order_id
            }, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Generate Collect Pay Request UPI Intent URI (UPI 2.0 collect)
        collect_uri = (
            f"upi://pay?"
            f"pa={merchant_vpa}"
            f"&pn={merchant_name}"
            f"&tr={payment.provider_order_id}"
            f"&am={amount}"
            f"&cu=INR"
            f"&mode=02"
            f"&tn=Collect+Request"
            f"&orgid=000000"
            f"&mc=0000"
        )

        # ✅ Dummy Transaction ID + RRN (you generate internally)
        vpa_txn_id = f"vpa_txn_{payment.id}"
        rrn = f"rrn_{payment.id}"

        # ✅ Response format matching CashBell
        return Response({
            "statusCode": 1,
            "message": "Collect Pay Generated Successfully",
            "orderId": order_id,
            "vpaTxnId": vpa_txn_id,
            "bankRRN": rrn,
            "amount": amount,
            "name": merchant_name,
            "collectUri": collect_uri
        }, status=status.HTTP_200_OK)


class CheckOrderStatusView(APIView):

    def post(self, request):
        d = request.data

        client_id = d.get("clientId")
        secret_key = d.get("secretKey")
        order_id = d.get("OrderId")

        # ✅ required validation
        missing = []
        if not client_id: missing.append("clientId")
        if not secret_key: missing.append("secretKey")
        if not order_id: missing.append("orderId")

        if missing:
            return Response({
                "statusCode": 0,
                "message": f"Missing fields: {', '.join(missing)}",
                "missingFields": missing
            }, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Authenticate
        api_key, merchant = _authenticate_api_client(client_id, secret_key)
        if not api_key or not merchant:
            return Response({
                "statusCode": 0,
                "message": "Invalid API credentials"
            }, status=status.HTTP_401_UNAUTHORIZED)

        # ✅ Fetch payment order
        try:
            payment = Payment.objects.get(merchant=merchant, order_id=order_id)
        except Payment.DoesNotExist:
            return Response({
                "statusCode": 0,
                "message": "Order not found",
                "orderId": order_id
            }, status=status.HTTP_404_NOT_FOUND)

        # ✅ If DB already has payment ID → final status
        if payment.provider_payment_id:
            return Response({
                "statusCode": 1,
                "message": "Order status fetched",
                "orderId": order_id,
                "providerOrderId": payment.provider_order_id,
                "providerPaymentId": payment.provider_payment_id,
                "status": payment.status,
                "amount": str(payment.amount),
                "vpa": payment.vpa,
                "updatedAt": payment.updated_at.isoformat()
            }, status=status.HTTP_200_OK)

        # ✅ If still pending — OPTIONAL Razorpay order status fetch
        provider_order_id = payment.provider_order_id
        if not provider_order_id:
            return Response({
                "statusCode": 0,
                "message": "Provider order not yet created",
                "orderId": order_id
            }, status=status.HTTP_400_BAD_REQUEST)

        # ✅ Call Razorpay (optional enhancement)
        try:
            import razorpay
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

            payments = client.order.payments(provider_order_id)
            items = payments.get("items", [])
        except Exception:
            items = []

        # ✅ If payment exists in Razorpay
        if items:
            payment_item = items[0]
            payment.provider_payment_id = payment_item["id"]
            payment.status = "paid" if payment_item["status"] == "captured" else "failed"
            payment.paid_at = timezone.now()
            payment.save(update_fields=["provider_payment_id", "status", "paid_at", "updated_at"])

        # ✅ RESPONSE
        return Response({
            "statusCode": 1,
            "message": "Order status fetched",
            "orderId": order_id,
            "providerOrderId": payment.provider_order_id,
            "providerPaymentId": payment.provider_payment_id,
            "status": payment.status,
            "amount": str(payment.amount),
            "vpa": payment.vpa,
            "updatedAt": payment.updated_at.isoformat()
        }, status=status.HTTP_200_OK)


def _two_dp(x: Decimal | None) -> str:
    if x is None:
        return "0.00"
    return f"{Decimal(x):.2f}"


def _parse_dates(request):
    start_s = (
        request.query_params.get("startDate")
        or request.query_params.get("fromDate")
    )
    end_s = (
        request.query_params.get("endDate")
        or request.query_params.get("toDate")
    )

    # fallback to body (if someone POSTs this endpoint)
    if (not start_s or not end_s) and hasattr(request, "data"):
        body = request.data or {}
        start_s = start_s or body.get("startDate") or body.get("fromDate")
        end_s = end_s or body.get("endDate") or body.get("toDate")

    def _parse_one(s: str | None) -> date | None:
        if not s:
            return None
        s = s.strip()
        # try ISO first
        try:
            return date.fromisoformat(s)
        except Exception:
            pass
        # try DD/MM/YYYY (matches your UI)
        try:
            return datetime.strptime(s, "%d/%m/%Y").date()
        except Exception:
            return None

    # defaults if not provided
    if not start_s and not end_s:
        start = timezone.localdate() - timedelta(days=60)
        end = timezone.localdate()
    else:
        start = _parse_one(start_s)
        end = _parse_one(end_s)
        if start is None:
            return None, None, None, "Invalid startDate/fromDate format. Use YYYY-MM-DD or DD/MM/YYYY."
        if end is None:
            return None, None, None, "Invalid endDate/toDate format. Use YYYY-MM-DD or DD/MM/YYYY."

    # validate ordering
    if start > end:
        return None, None, None, "startDate/fromDate must be on or before endDate/toDate."

    # end is inclusive for UI, exclusive (+1 day) for ORM
    end_plus = end + timedelta(days=1)
    return start, end, end_plus, None


class DashboardView(APIView):

    def get(self, request):
        # credentials (inline)
        client_id = request.query_params.get("clientId") or \
                    request.headers.get("X-Client-Id") or \
                    request.META.get("HTTP_X_CLIENT_ID") or \
                    request.headers.get("clientId") or \
                    request.META.get("HTTP_CLIENTID")

        secret_key = request.query_params.get("secretKey") or \
                     request.headers.get("X-Client-Secret") or \
                     request.META.get("HTTP_X_CLIENT_SECRET") or \
                     request.headers.get("secretKey") or \
                     request.META.get("HTTP_SECRETKEY")

        if (not client_id or not secret_key) and hasattr(request, "data"):
            d = request.data or {}
            client_id = client_id or d.get("clientId")
            secret_key = secret_key or d.get("secretKey")

        if not client_id or not secret_key:
            return Response({"Statuscode": 0, "Message": "Missing credentials"},
                            status=status.HTTP_400_BAD_REQUEST)

        # auth
        api_key, merchant = _authenticate_api_client(client_id, secret_key)
        if not api_key or not merchant:
            return Response({"Statuscode": 0, "Message": "Invalid API credentials"},
                            status=status.HTTP_401_UNAUTHORIZED)

        # date window (now supports start/end & from/to + both formats)
        start_d, end_d, end_plus, err = _parse_dates(request)
        if err:
            return Response({"Statuscode": 0, "Message": err},
                            status=status.HTTP_400_BAD_REQUEST)

        # base queryset
        base = Payment.objects.filter(
            merchant=merchant,
            created_at__date__gte=start_d,
            created_at__date__lt=end_plus
        )

        # status groups
        success_q = Q(status__in=["success", "paid", "completed"])
        failed_q = Q(status="failed")
        pending_q = Q(status="pending")
        cancelled_q = Q(status="cancelled")

        # aggregates (Decimal-safe)
        agg = base.aggregate(
            total=Count("id"),
            success=Count("id", filter=success_q),
            failed=Count("id", filter=failed_q),
            pending=Count("id", filter=pending_q),
            cancelled=Count("id", filter=cancelled_q),
            volume_success=Coalesce(
                Sum("amount", filter=success_q),
                V(Decimal("0.00"), output_field=DecimalField(max_digits=18, decimal_places=2)),
                output_field=DecimalField(max_digits=18, decimal_places=2),
            ),
            volume_total=Coalesce(
                Sum("amount"),
                V(Decimal("0.00"), output_field=DecimalField(max_digits=18, decimal_places=2)),
                output_field=DecimalField(max_digits=18, decimal_places=2),
            ),
        )

        total = agg["total"] or 0
        success_count = agg["success"] or 0
        failed_count = agg["failed"] or 0
        pending_count = agg["pending"] or 0
        cancelled_count = agg["cancelled"] or 0
        success_rate = round((success_count / total) * 100, 2) if total else 0.0

        donut = {
            "total": total,
            "success": success_count,
            "failed": failed_count,
            "pending": pending_count,
            "cancelled": cancelled_count,
            "successRate": success_rate,
        }

        # service-wise (Payin only)
        service = [{
            "service": "Payin",
            "successCount": success_count,
            "successVolume": _two_dp(agg["volume_success"]),
            "currency": "INR",
        }]

        # monthly
        monthly = (
            base.annotate(m=TruncMonth("created_at"))
                .values("m")
                .annotate(
                    txCount=Count("id"),
                    txVolume=Coalesce(
                        Sum("amount"),
                        V(Decimal("0.00"), output_field=DecimalField(max_digits=18, decimal_places=2)),
                        output_field=DecimalField(max_digits=18, decimal_places=2),
                    ),
                )
                .order_by("m")
        )
        monthly_rows = [{
            "month": row["m"].strftime("%B %Y"),
            "transactionCount": row["txCount"],
            "transactionVolume": _two_dp(row["txVolume"]),
            "currency": "INR",
        } for row in monthly]

        # latest
        try:
            latest_limit = int(request.query_params.get("limit", 10))
        except Exception:
            latest_limit = 10
        latest_limit = max(1, min(latest_limit, 100))  # clamp 1..100

        latest = (
            base.order_by("-created_at")
                .values("order_id", "provider_order_id", "status", "amount",
                        "payer_name", "payer_mobile", "created_at")[:latest_limit]
        )
        latest_rows = [{
            "orderId": p["order_id"],
            "providerOrderId": p["provider_order_id"],
            "status": p["status"],
            "amount": _two_dp(p["amount"]),
            "currency": "INR",
            "payerName": p["payer_name"],
            "payerMobile": p["payer_mobile"],
            "txnDate": p["created_at"].isoformat(),
        } for p in latest]

        payload = {
            "Statuscode": 1,
            "Message": "Dashboard data",
            "filters": {"startDate": start_d.isoformat(), "endDate": end_d.isoformat()},
            "widgets": {
                "successFailure": donut,
                "serviceSuccess": service,
                "monthly": monthly_rows,
                "latestTransactions": {"count": len(latest_rows), "rows": latest_rows}
            }
        }
        return Response(payload, status=status.HTTP_200_OK)


ALLOWED_STATUSES = {
    "pending",
    "paid",
    "failed",
    "cancelled",
    "attempted",
    "expired",
    "created",
    "refunded",
    "success",
    "completed",
}


def _parse_statuses(request):
    """
    Accepts:
      - ?status=paid,failed
      - ?status=paid&status=failed
      - body: {"status": ["paid","failed"]} or {"status": "paid,failed"}
    Returns a normalized set (lowercase), or empty set for 'no status filter'.
    """
    raw = []

    # query params
    raw += request.query_params.getlist("status")
    if not raw:
        s = request.query_params.get("status")
        if s:
            raw = [s]

    # body fallback
    if not raw and hasattr(request, "data") and request.data:
        body_s = request.data.get("status")
        if isinstance(body_s, list):
            raw = body_s
        elif isinstance(body_s, str):
            raw = [body_s]

    items = []
    for item in raw:
        if item is None:
            continue
        # split comma-lists
        for token in str(item).split(","):
            t = token.strip().lower()
            if not t:
                continue
            # normalize success/completed -> paid for filtering convenience
            if t in {"success", "completed"}:
                t = "paid"
            if t in ALLOWED_STATUSES:
                items.append(t)

    return set(items)


class DashboardV2View(APIView):
    """
    GET /api/dashboard-v2?fromDate=2025-11-01&toDate=2025-11-12&status=paid,failed&limit=10
    or POST with same fields in body.
    """
    def get(self, request):
        return self._handle(request)

    def post(self, request):
        return self._handle(request)

    def _handle(self, request):
        # ---- credentials (same behavior as your DashboardView) ----
        client_id = (
            request.query_params.get("clientId")
            or request.headers.get("X-Client-Id")
            or request.META.get("HTTP_X_CLIENT_ID")
            or request.headers.get("clientId")
            or request.META.get("HTTP_CLIENTID")
        )
        secret_key = (
            request.query_params.get("secretKey")
            or request.headers.get("X-Client-Secret")
            or request.META.get("HTTP_X_CLIENT_SECRET")
            or request.headers.get("secretKey")
            or request.META.get("HTTP_SECRETKEY")
        )
        if (not client_id or not secret_key) and hasattr(request, "data"):
            d = request.data or {}
            client_id = client_id or d.get("clientId")
            secret_key = secret_key or d.get("secretKey")

        if not client_id or not secret_key:
            return Response({"Statuscode": 0, "Message": "Missing credentials"},
                            status=status.HTTP_400_BAD_REQUEST)

        api_key, merchant = _authenticate_api_client(client_id, secret_key)
        if not api_key or not merchant:
            return Response({"Statuscode": 0, "Message": "Invalid API credentials"},
                            status=status.HTTP_401_UNAUTHORIZED)

        # ---- filters ----
        start_d, end_d, end_plus, err = _parse_dates(request)
        if err:
            return Response({"Statuscode": 0, "Message": err},
                            status=status.HTTP_400_BAD_REQUEST)

        selected_statuses = _parse_statuses(request)  # empty set means "no status filter"

        # base queryset for the window
        base = Payment.objects.filter(
            merchant=merchant,
            created_at__date__gte=start_d,
            created_at__date__lt=end_plus
        )

        if selected_statuses:
            base = base.filter(status__in=list(selected_statuses))

        # ---- status-wise donut (counts, % and volume per status) ----
        # include only statuses present in ALLOWED_STATUSES (normalized)
        status_cases = {s: Q(status=s) for s in
                        ["pending", "paid", "failed", "cancelled", "attempted", "expired", "created", "refunded"]}

        donut_agg = base.aggregate(
            total=Count("id"),
            **{f"c_{k}": Count("id", filter=q) for k, q in status_cases.items()},
            **{f"v_{k}": Coalesce(
                Sum("amount", filter=q),
                V(Decimal("0.00"), output_field=DecimalField(max_digits=18, decimal_places=2)),
                output_field=DecimalField(max_digits=18, decimal_places=2),
            ) for k, q in status_cases.items()},
        )
        total = donut_agg.get("total") or 0

        def pct(n):
            return round((n / total) * 100, 2) if total else 0.0

        status_items = []
        for key in ["failed", "attempted", "expired", "paid", "created", "pending", "cancelled", "refunded"]:
            cnt = donut_agg.get(f"c_{key}") or 0
            vol = donut_agg.get(f"v_{key}") or Decimal("0.00")
            status_items.append({
                "status": key,
                "count": cnt,
                "percent": pct(cnt),
                "volume": _two_dp(vol),
                "currency": "INR",
            })

        # ---- intent-wise performance (like the grid in your screenshot) ----
        # Count-wise buckets
        count_paid = donut_agg["c_paid"] or 0
        count_failure = (donut_agg["c_failed"] or 0) + (donut_agg["c_cancelled"] or 0) + (donut_agg["c_expired"] or 0)
        count_pending = (donut_agg["c_pending"] or 0) + (donut_agg["c_attempted"] or 0) + (donut_agg["c_created"] or 0)
        count_refund = donut_agg["c_refunded"] or 0
        count_cancelled = donut_agg["c_cancelled"] or 0  # shown separately if you want

        # Volume-wise buckets
        vol_success = donut_agg["v_paid"] or Decimal("0.00")
        vol_failure = (donut_agg["v_failed"] or Decimal("0.00")) + \
                      (donut_agg["v_cancelled"] or Decimal("0.00")) + \
                      (donut_agg["v_expired"] or Decimal("0.00"))
        vol_pending = (donut_agg["v_pending"] or Decimal("0.00")) + \
                      (donut_agg["v_attempted"] or Decimal("0.00")) + \
                      (donut_agg["v_created"] or Decimal("0.00"))
        vol_refund = donut_agg["v_refunded"] or Decimal("0.00")
        vol_cancelled = donut_agg["v_cancelled"] or Decimal("0.00")

        intent = [{
            "paymentType": "Intent",
            "countWise": {
                "paid": count_paid,
                "failure": count_failure,
                "pending": count_pending,
                "refunded": count_refund,
                "cancelled": count_cancelled,
            },
            "volumeWise": {
                "success": _two_dp(vol_success),
                "failure": _two_dp(vol_failure),
                "pending": _two_dp(vol_pending),
                "refunded": _two_dp(vol_refund),
                "cancelled": _two_dp(vol_cancelled),
                "currency": "INR",
            }
        }]

        # ---- monthly trend ----
        monthly = (
            base.annotate(m=TruncMonth("created_at"))
                .values("m")
                .annotate(
                    txCount=Count("id"),
                    txVolume=Coalesce(
                        Sum("amount"),
                        V(Decimal("0.00"), output_field=DecimalField(max_digits=18, decimal_places=2)),
                        output_field=DecimalField(max_digits=18, decimal_places=2),
                    ),
                ).order_by("m")
        )
        monthly_rows = [{
            "month": row["m"].strftime("%B %Y"),
            "transactionCount": row["txCount"],
            "transactionVolume": _two_dp(row["txVolume"]),
            "currency": "INR",
        } for row in monthly]

        # ---- latest transactions ----
        try:
            latest_limit = int(request.query_params.get("limit", 10))
        except Exception:
            latest_limit = 10
        latest_limit = max(1, min(latest_limit, 100))

        latest = (
            base.order_by("-created_at")
                .values("order_id", "provider_order_id", "status", "amount",
                        "payer_name", "payer_mobile", "created_at")[:latest_limit]
        )
        latest_rows = [{
            "orderId": p["order_id"],
            "providerOrderId": p["provider_order_id"],
            "status": p["status"],
            "amount": _two_dp(p["amount"]),
            "currency": "INR",
            "payerName": p["payer_name"],
            "payerMobile": p["payer_mobile"],
            "txnDate": p["created_at"].isoformat(),
        } for p in latest]

        payload = {
            "Statuscode": 1,
            "Message": "Dashboard data",
            "filters": {
                "startDate": start_d.isoformat(),
                "endDate": end_d.isoformat(),
                "status": sorted(list(selected_statuses)) if selected_statuses else [],
            },
            "widgets": {
                # for the donut chart
                "statusWiseOrder": {
                    "total": total,
                    "items": status_items
                },
                # for your grid
                "intentWisePerformance": intent,
                # optional: keep your old widgets if the UI uses them
                "monthly": monthly_rows,
                "latestTransactions": {"count": len(latest_rows), "rows": latest_rows},
            }
        }
        return Response(payload, status=status.HTTP_200_OK)