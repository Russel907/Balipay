# gateway/tasks.py
# Run this as a PythonAnywhere scheduled task every minute

import django
import os
import sys
import time

# Setup Django
sys.path.insert(0, '/home/sahanasv')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'balipay.settings')
django.setup()

from django.utils import timezone
from datetime import timedelta
from gateway.models import Payment
from gateway.phonepe_client import check_phonepe_order_status

TERMINAL_STATUSES = {"paid", "failed", "expired", "cancelled", "refunded"}
POLL_TIMEOUT_MINUTES = 20


def poll_pending_payments():
    # Only poll payments that are pending and created within last 20 mins
    cutoff = timezone.now() - timedelta(minutes=POLL_TIMEOUT_MINUTES)
    
    pending_payments = Payment.objects.filter(
        status__in=["pending", "attempted", "created"],
        created_at__gte=cutoff,
        provider_order_id__isnull=False
    )

    for payment in pending_payments:
        try:
            resp = check_phonepe_order_status(payment.order_id)
            state = resp.get("state")  # ROOT level state only

            if state == "COMPLETED":
                payment.status = Payment.STATUS_PAID
                payment.paid_at = timezone.now()
            elif state == "FAILED":
                payment.status = Payment.STATUS_FAILED
            elif state == "EXPIRED":
                payment.status = Payment.STATUS_EXPIRED
            elif state == "PENDING":
                payment.status = Payment.STATUS_PENDING
            elif state == "ATTEMPTED":
                payment.status = Payment.STATUS_ATTEMPTED

            payment.attempts += 1
            payment.provider_status_response = resp
            payment.save(update_fields=[
                "status", "provider_status_response",
                "paid_at", "attempts", "updated_at"
            ])

        except Exception as e:
            print(f"Error polling {payment.order_id}: {e}")


if __name__ == "__main__":
    poll_pending_payments()