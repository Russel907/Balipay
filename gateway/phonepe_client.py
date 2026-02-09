# gateway/phonepe_client.py
import requests
import json
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
def create_phonepe_payment(payload: dict):
    access_token = get_tsp_token()

    url = "https://api-preprod.phonepe.com/apis/pg-sandbox/payments/v2/pay"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"O-Bearer {access_token}",
        "X-MERCHANT-ID": settings.PHONEPE_MERCHANT_ID,
    }

    response = requests.post(
        url,
        headers=headers,
        json=payload,
        timeout=20
    )

    if response.status_code not in (200, 201):
        raise PhonePeError(
            f"Payment error {response.status_code}: {response.text}"
        )

    return response.json()

# def create_phonepe_sdk_order(payload: dict):
#     """Creates SDK order and returns token for UI initialization"""
#     access_token = get_tsp_token()
    
#     url = "https://api-preprod.phonepe.com/apis/pg-sandbox/v2/order/create"
    
#     headers = {
#         "Content-Type": "application/json",
#         "Authorization": f"O-Bearer {access_token}",
#         "X-MERCHANT-ID": settings.PHONEPE_MERCHANT_ID,
#     }
    
#     # Correct payload structure
#     sdk_payload = {
#         "merchantOrderId": payload["merchantTransactionId"],
#         "amount": payload["amount"],
#         "constraints": []  # Add constraints if needed
#     }
    
#     response = requests.post(url, headers=headers, json=sdk_payload, timeout=20)
    
#     if response.status_code not in (200, 201):
#         raise PhonePeError(f"SDK Order error {response.status_code}: {response.text}")
    
#     return response.json()  # Returns {orderId, state, expireAt, token}
def create_phonepe_sdk_order(merchant_order_id: str, amount_in_paise: int):
    access_token = get_tsp_token()

    url = "https://api-preprod.phonepe.com/apis/pg-sandbox/v2/order/create"

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"O-Bearer {access_token}",
        "X-MERCHANT-ID": settings.PHONEPE_MERCHANT_ID,
    }

    payload = {
        "merchantOrderId": merchant_order_id,
        "amount": amount_in_paise,
        "constraints": []
    }

    response = requests.post(url, headers=headers, json=payload, timeout=20)

    if response.status_code not in (200, 201):
        raise PhonePeError(
            f"SDK Order error {response.status_code}: {response.text}"
        )

    return response.json()
