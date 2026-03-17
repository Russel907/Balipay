# gateway/phonepe_client.py

import time
import requests
import logging
from django.conf import settings
from django.utils import timezone
from gateway.models import Payment

logger = logging.getLogger(__name__)

class PhonePeError(Exception):
    pass


# =====================================
# TOKEN CACHE
# =====================================
_token_cache = {
    "token": None,
    "expires_at": 0
}


# =====================================
# 1. GET TSP AUTH TOKEN (CACHED)
# =====================================
def get_tsp_token():
    buffer = 4 * 60  # Refresh 4 minutes before expiry

    if _token_cache["token"] and time.time() < (_token_cache["expires_at"] - buffer):
        return _token_cache["token"]

    url = "https://api-preprod.phonepe.com/apis/pg-sandbox/v1/oauth/token"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "client_id": settings.PHONEPE_CLIENT_ID,
        "client_secret": settings.PHONEPE_CLIENT_SECRET,
        "client_version": str(settings.PHONEPE_CLIENT_VERSION),
        "grant_type": "client_credentials",
    }

    response = requests.post(url, headers=headers, data=data, timeout=15)

    if response.status_code != 200:
        raise PhonePeError(
            f"Token error {response.status_code}: {response.text}"
        )

    resp = response.json()
    _token_cache["token"] = resp["access_token"]
    _token_cache["expires_at"] = time.time() + resp.get("expires_in", 3600)

    return _token_cache["token"]


# =====================================
# 2. CREATE PAYMENT (CUSTOM CHECKOUT)
# =====================================
def create_phonepe_payment(
    merchant_order_id: str,
    amount_in_paise: int,
    # callback_url: str,
    # redirect_url: str,
    device_os: str = "ANDROID",
    merchant_mid: str = None,
    merchant_domain: str = None,
):
    access_token = get_tsp_token()

    url = "https://api-preprod.phonepe.com/apis/pg-sandbox/payments/v2/pay"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"O-Bearer {access_token}",
        "X-MERCHANT-ID": merchant_mid or settings.PHONEPE_MERCHANT_ID,
        "X-SOURCE": "API",
        "X-SOURCE-CHANNEL": "android",
        "X-BROWSER-FINGERPRINT": "testfingerprint123",
        "X-MERCHANT-DOMAIN": merchant_domain or settings.BASE_URL,
        "X-MERCHANT-IP": "127.0.0.1",
        "X-MERCHANT-APP-ID": "com.balipay.app",
        "X-SOURCE-CHANNEL-VERSION": "1"
    }

    if device_os == "WEB":
        payment_mode = {"type": "UPI_QR"}
    else:
        payment_mode = {
            "type": "UPI_INTENT",
            "targetApp": "com.phonepe.app"
        }

    payload = {
        "merchantOrderId": merchant_order_id,
        "amount": amount_in_paise,
        "expireAfter": 1200,
        # "callbackUrl": callback_url,
        # "redirectUrl": redirect_url,
        "deviceContext": {
            "deviceOS": device_os
        },
        "paymentFlow": {
            "type": "PG",
            "paymentMode": payment_mode
        },
        "metaInfo": {
            "udf1": "",
            "udf2": "",
            "udf3": "",
            "udf4": "",
            "udf5": ""
        }
    }

    response = requests.post(url, headers=headers, json=payload, timeout=20)
    print("PhonePe full response:", response.json())

    if response.status_code not in (200, 201):
        raise PhonePeError(
            f"Payment error {response.status_code}: {response.text}"
        )

    return response.json()


def create_phonepe_qr_payment(
    merchant_order_id: str,
    amount_in_paise: int,
    merchant_mid: str = None,
    merchant_domain: str = None,
):
    access_token = get_tsp_token()

    url = "https://api-preprod.phonepe.com/apis/pg-sandbox/payments/v2/pay"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"O-Bearer {access_token}",
        "X-MERCHANT-ID": merchant_mid or settings.PHONEPE_MERCHANT_ID,
        "X-SOURCE": "API",
        "X-SOURCE-CHANNEL": "web",
        "X-BROWSER-FINGERPRINT": "desktop_fingerprint",
        "X-MERCHANT-DOMAIN": merchant_domain or settings.BASE_URL,
        "X-MERCHANT-IP": "127.0.0.1",
        "X-MERCHANT-APP-ID": "com.balipay.web",
        "X-SOURCE-CHANNEL-VERSION": "1"
    }

    payload = {
        "merchantOrderId": merchant_order_id,
        "amount": amount_in_paise,
        "expireAfter": 480,
        "paymentFlow": {
            "type": "PG",
            "paymentMode": {
                "type": "UPI_QR"
            }
        },
        "metaInfo": {
            "udf1": "",
            "udf2": "",
            "udf3": "",
            "udf4": "",
            "udf5": ""
        }
    }

    response = requests.post(url, headers=headers, json=payload, timeout=20)

    if response.status_code not in (200, 201):
        raise PhonePeError(
            f"QR Payment error {response.status_code}: {response.text}"
        )

    return response.json()

def check_phonepe_refund_status(merchant_refund_id: str, merchant_mid: str = None):
    access_token = get_tsp_token()

    url = f"https://api-preprod.phonepe.com/apis/pg-sandbox/payments/v2/refund/{merchant_refund_id}/status"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"O-Bearer {access_token}",
        "X-MERCHANT-ID": merchant_mid or settings.PHONEPE_MERCHANT_ID,
        "X-SOURCE": "API",
        "X-SOURCE-CHANNEL": "web",
        "X-MERCHANT-IP": "127.0.0.1"
    }

    response = requests.get(url, headers=headers, timeout=20)

    if response.status_code != 200:
        raise PhonePeError(
            f"Refund status error {response.status_code}: {response.text}"
        )

    return response.json()
# =====================================
# 3. CHECK ORDER STATUS
# =====================================
def check_phonepe_order_status(merchant_order_id: str, merchant_mid: str = None):
    access_token = get_tsp_token()

    url = f"https://api-preprod.phonepe.com/apis/pg-sandbox/payments/v2/order/{merchant_order_id}/status"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"O-Bearer {access_token}",
        "X-MERCHANT-ID": merchant_mid or settings.PHONEPE_MERCHANT_ID,
        "X-SOURCE": "API",
        "X-SOURCE-CHANNEL": "web"
    }

    response = requests.get(url, headers=headers, timeout=20)

    if response.status_code != 200:
        raise PhonePeError(
            f"Status error {response.status_code}: {response.text}"
        )

    return response.json()

def poll_phonepe_order_until_terminal(merchant_order_id: str, timeout_seconds=1200):
    start_time = time.time()

    schedule = [
        (3, 30),
        (6, 60),
        (10, 60),
        (30, 60),
        (60, 999999)
    ]

    TERMINAL_STATUSES = [
        Payment.STATUS_PAID,
        Payment.STATUS_FAILED,
        Payment.STATUS_EXPIRED,
        Payment.STATUS_CANCELLED,
        Payment.STATUS_REFUNDED
    ]

    for interval, duration in schedule:
        segment_start = time.time()
        while time.time() - segment_start < duration:

            if time.time() - start_time >= timeout_seconds:
                return

            # ✅ ALWAYS check db FIRST before doing anything
            try:
                payment = Payment.objects.get(order_id=merchant_order_id)
            except Payment.DoesNotExist:
                return

            # ✅ If webhook already set terminal status — STOP immediately
            if payment.status in TERMINAL_STATUSES:
                logger.info("Polling stopped - webhook already set terminal status: %s for %s", payment.status, merchant_order_id)
                return

            try:
                status_response = check_phonepe_order_status(merchant_order_id)
                state = status_response.get("state")

                # ✅ Refresh payment from db again (webhook might have updated during API call)
                payment = Payment.objects.get(order_id=merchant_order_id)
                
                # ✅ Check again after refresh
                if payment.status in TERMINAL_STATUSES:
                    logger.info("Polling stopped after refresh - terminal status: %s", payment.status)
                    return

                payment.provider_status_response = status_response
                payment.attempts = payment.attempts + 1

                if state == "COMPLETED":
                    payment.status = Payment.STATUS_PAID
                    payment.paid_at = timezone.now()
                    payment.save(update_fields=["status", "provider_status_response", "paid_at", "attempts", "updated_at"])
                    return

                elif state == "FAILED":
                    payment.status = Payment.STATUS_FAILED
                    payment.save(update_fields=["status", "provider_status_response", "attempts", "updated_at"])
                    return

                elif state == "EXPIRED":
                    payment.status = Payment.STATUS_EXPIRED
                    payment.save(update_fields=["status", "provider_status_response", "attempts", "updated_at"])
                    return

                else:
                    # PENDING - just save status response, don't change status
                    payment.save(update_fields=["provider_status_response", "attempts", "updated_at"])

            except Exception as exc:
                logger.exception("Polling error for %s: %s", merchant_order_id, exc)

            time.sleep(interval)