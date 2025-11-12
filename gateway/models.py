from django.db import models, transaction
import secrets
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta


ENTITY_TYPE_CHOICES = (
    ("proprietorship", "Proprietorship"),
    ("partnership_llp", "Partnership/LLP"),
    ("pvt_public", "Pvt. Ltd. / Public Ltd"),
    ("person_company", "Person Company"),
    ("partnership_firm", "Partnership Firm"),
)

class Merchant(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="merchant_profile")
    business_name = models.CharField(max_length=255, blank=True)
    contact_name = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    entity_type = models.CharField(max_length=50, choices=ENTITY_TYPE_CHOICES, blank=True, null=True)
    business_address = models.TextField(blank=True, null=True)
    pincode = models.CharField(max_length=10, blank=True, null=True)
    webhook_secret = models.CharField(max_length=128, blank=True, null=True)
    is_active = models.BooleanField(default=False)  # becomes True after OTP verification
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.business_name or self.contact_name or self.email

class OTP(models.Model):
    merchant = models.ForeignKey("Merchant", on_delete=models.CASCADE, related_name="otps")
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    attempts = models.PositiveSmallIntegerField(default=0)
    consumed = models.BooleanField(default=False) 
    provider_verification_id = models.CharField(max_length=64, blank=True, null=True)
    provider_transaction_id = models.CharField(max_length=128, blank=True, null=True) 

    class Meta:
        indexes = [
            models.Index(fields=["merchant", "created_at"]),
        ]

    def is_expired(self):
        return timezone.now() > self.expires_at or self.consumed

    @classmethod
    def generate_code(cls):
        return f"{secrets.randbelow(1000000):06d}"

    @classmethod
    def create_otp(cls, merchant, ttl_seconds=600):
        code = cls.generate_code()
        now = timezone.now()
        return cls.objects.create(
            merchant=merchant,
            code=code,
            expires_at=now + timedelta(seconds=ttl_seconds),
            attempts=0,
            consumed=False,
        )


API_MODE_CHOICES = (
    ("test", "Test"),
    ("live", "Live"),
)


def gen_raw_key(prefix: str):
    # produces a URL-safe secret
    return prefix + secrets.token_urlsafe(24)


class APIKey(models.Model):
    merchant = models.ForeignKey("Merchant", on_delete=models.CASCADE, related_name="api_keys")
    key_id = models.CharField(max_length=64, unique=True)           
    hashed_secret = models.CharField(max_length=128)                
    name = models.CharField(max_length=255, blank=True, null=True)
    mode = models.CharField(max_length=8, choices=API_MODE_CHOICES, default="test")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(blank=True, null=True)        
    revoked = models.BooleanField(default=False)
    last_used_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=["merchant", "created_at"]),
            models.Index(fields=["key_id"]),
        ]

    def __str__(self):
        return f"{self.key_id} ({self.merchant_id})"

    @classmethod
    def _make_key_id(cls, raw_secret: str):
        suffix = secrets.token_hex(6)
        if raw_secret.startswith("balipay_live_") or raw_secret.startswith("balipay_test_"):
            prefix = raw_secret.split("_")[0] + "_" + raw_secret.split("_")[1]  # balipay_test
            return f"{prefix}_{suffix}"
        return f"api_{suffix}"

    @classmethod
    def create_key(cls, merchant, name=None, mode="test", ttl_seconds: int = None):
        prefix = "balipay_test_" if mode == "test" else "balipay_live_"
        raw = gen_raw_key(prefix=prefix)
        key_id = cls._make_key_id(raw)
        hashed = make_password(raw)

        expires_at = None
        if ttl_seconds:
            expires_at = timezone.now() + timedelta(seconds=ttl_seconds)

        with transaction.atomic():
            obj = cls.objects.create(
                merchant=merchant,
                key_id=key_id,
                hashed_secret=hashed,
                name=name,
                mode=mode,
                expires_at=expires_at,
                revoked=False,
            )
        return obj, raw



class Payment(models.Model):
    STATUS_PENDING = 'pending'
    STATUS_PAID = 'paid'
    STATUS_FAILED = 'failed'
    STATUS_CANCELLED = 'cancelled'
    STATUS_ATTEMPTED = 'attempted'
    STATUS_EXPIRED = 'expired'
    STATUS_CREATED = 'created'
    STATUS_REFUNDED = 'refunded'

    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_PAID, "Paid"),
        (STATUS_FAILED, "Failed"),
        (STATUS_CANCELLED, "Cancelled"),
        (STATUS_ATTEMPTED, "Attempted"),
        (STATUS_EXPIRED, "Expired"),
        (STATUS_CREATED, "Created"),
        (STATUS_REFUNDED, "Refunded"),  
    ]

    merchant = models.ForeignKey("Merchant", on_delete=models.CASCADE, related_name="payments")
    order_id = models.CharField(max_length=100)                     # clientOrderId (merchant)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    currency = models.CharField(max_length=8, default="INR")        # store currency explicitly
    amount_in_paise = models.BigIntegerField(null=True, blank=True) # optional cached integer paise value

    vpa = models.CharField(max_length=100, blank=True, null=True)

    status = models.CharField(max_length=20, default=STATUS_PENDING, choices=STATUS_CHOICES)

    # Provider IDs (store separately for clarity)
    provider_order_id = models.CharField(max_length=128, blank=True, null=True)   # order_xxx (Razorpay order)
    provider_payment_id = models.CharField(max_length=128, blank=True, null=True) # pay_xxx (Razorpay payment)

    # Raw provider data for debugging / reconciliation
    provider_order_response = models.JSONField(blank=True, null=True)   # store the order create response
    provider_payment_response = models.JSONField(blank=True, null=True) # store payment/capture responses if desired

    # Optional idempotency / audit fields
    idempotency_key = models.CharField(max_length=255, blank=True, null=True)
    attempts = models.IntegerField(default=0)

    # Payer info
    payer_name = models.CharField(max_length=255, blank=True, null=True)
    payer_mobile = models.CharField(max_length=20, blank=True, null=True)
    payer_email = models.EmailField(blank=True, null=True)

    # lifecycle times
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    paid_at = models.DateTimeField(blank=True, null=True)
    cancelled_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["merchant", "order_id"], name="uniq_merchant_order")
        ]
        indexes = [
            models.Index(fields=["provider_order_id"]),
            models.Index(fields=["provider_payment_id"]),
        ]

    def __str__(self):
        return f"{self.merchant.business_name} - {self.order_id} - {self.amount}"