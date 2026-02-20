# gateway/phonepe_client.py

import requests
from django.conf import settings


class PhonePeError(Exception):
    pass


# =====================================
# 1. GET TSP AUTH TOKEN (SANDBOX)
# =====================================
def get_tsp_token():
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

    return response.json()["access_token"]


# =====================================
# 2. CREATE PAYMENT (CUSTOM CHECKOUT)
# =====================================
def create_phonepe_payment(
    merchant_order_id: str, 
    amount_in_paise: int,
    callback_url: str,  # ✅ Added
    redirect_url: str   # ✅ Added
):
    access_token = get_tsp_token()

    url = "https://api-preprod.phonepe.com/apis/pg-sandbox/payments/v2/pay"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"O-Bearer {access_token}",
        "X-MERCHANT-ID": settings.PHONEPE_MERCHANT_ID,
        "X-SOURCE": "API",
        "X-SOURCE-CHANNEL": "web",
        "X-BROWSER-FINGERPRINT": "testfingerprint123",
        "X-MERCHANT-DOMAIN": "https://yourdomain.com",
        "X-MERCHANT-IP": "127.0.0.1",
        "X-MERCHANT-APP-ID": "com.balipay.app",
        "X-SOURCE-CHANNEL-VERSION": "1"
    }

    payload = {
        "merchantOrderId": merchant_order_id,
        "amount": amount_in_paise,
        "expireAfter": 1200,
        "callbackUrl": callback_url,      # ✅ Added
        "redirectUrl": redirect_url,      # ✅ Added
        "deviceContext": {
            "deviceOS": "ANDROID"
        },
        "paymentFlow": {
            "type": "PG",
            "paymentMode": {
                "type": "UPI_INTENT",
                "targetApp": "com.phonepe.app"
            }
        }
    }

    response = requests.post(url, headers=headers, json=payload, timeout=20)

    if response.status_code not in (200, 201):
        raise PhonePeError(
            f"Payment error {response.status_code}: {response.text}"
        )

    return response.json()


# =====================================
# 3. CHECK ORDER STATUS (CORRECT)
# =====================================
def check_phonepe_order_status(merchant_order_id: str):
    access_token = get_tsp_token()

    url = f"https://api-preprod.phonepe.com/apis/pg-sandbox/payments/v2/order/{merchant_order_id}/status"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"O-Bearer {access_token}",
        "X-MERCHANT-ID": settings.PHONEPE_MERCHANT_ID,
        "X-SOURCE": "API",
        "X-SOURCE-CHANNEL": "web"
    }

    response = requests.get(url, headers=headers, timeout=20)

    if response.status_code != 200:
        raise PhonePeError(
            f"Status error {response.status_code}: {response.text}"
        )

    return response.json()
