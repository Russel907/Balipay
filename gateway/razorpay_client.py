# payments/razorpay_client.py

import requests
import logging
from django.conf import settings


logger = logging.getLogger(__name__)
RAZORPAY_ORDERS_URL = "https://api.razorpay.com/v1/orders"
DEFAULT_TIMEOUT = 10


def _mask_key(k):
    if not k:
        return "None"
    if len(k) <= 10:
        return k[:3] + "..."
    return k[:6] + "..." + k[-4:]

def create_razorpay_order(auth, amount_in_paise, receipt, notes=None, idempotency_key=None, timeout=DEFAULT_TIMEOUT):
    if auth is None:
        auth = (getattr(settings, "RAZORPAY_KEY_ID", None), getattr(settings, "RAZORPAY_KEY_SECRET", None))

    key, secret = auth if isinstance(auth, (list, tuple)) and len(auth) == 2 else (None, None)
    logger.debug("Creating Razorpay order with key=%s receipt=%s idempotency=%s", _mask_key(key), receipt, idempotency_key)

    data = {
        "amount": amount_in_paise,
        "currency": "INR",
        "receipt": receipt,
        "notes": notes or {}
    }

    # Try SDK first (optional)
    try:
        import razorpay
        client = razorpay.Client(auth=(key, secret))
        return client.order.create(data=data)
    except Exception as e:
        logger.debug("razorpay SDK create failed or not available, falling back to HTTP. err=%s", getattr(e, "args", e))

    headers = {"Content-Type": "application/json"}
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

    resp = requests.post(
        RAZORPAY_ORDERS_URL,
        auth=(key, secret),
        json=data,
        headers=headers,
        timeout=timeout,
    )

    if resp.status_code == 401:
        # Log masked key and the response text for debugging (but avoid secrets)
        logger.error("Razorpay 401 Unauthorized. key=%s receipt=%s idempotency=%s response=%s",
                     _mask_key(key), receipt, idempotency_key, resp.text[:1000])
    resp.raise_for_status()
    return resp.json()