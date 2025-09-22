from django.db import models
import uuid
import secrets
from django.contrib.auth.hashers import make_password


class Merchant(models.Model):
    business_name = models.CharField(max_length=255)
    # upi_id = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=15, blank=True, null=True)
    business_type = models.CharField(max_length=100, blank=True, null=True)
    gstin = models.CharField(max_length=15, blank=True, null=True)
    business_address = models.TextField(blank=True, null=True)
    callback_url = models.URLField(blank=True, null=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128) 

    api_key = models.CharField(max_length=100, unique=True, editable=False)

    webhook_secret = models.CharField(max_length=64, editable=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if not self.api_key:
            env_prefix = "balipay_test_"  
            random_part = secrets.token_urlsafe(24) 
            self.api_key = env_prefix + random_part

        if not self.webhook_secret:
            self.webhook_secret = secrets.token_hex(32)

        if self.password and not self.password.startswith("pbkdf2_"):
            self.password = make_password(self.password)
        
        super().save(*args, **kwargs)

    def __str__(self):
        return self.business_name
    
class Payment(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('failed', 'Failed'),
    ]
    merchant = models.ForeignKey(Merchant, on_delete=models.CASCADE, related_name="payments")
    order_id = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    vpa = models.CharField(max_length=100) 
    status = models.CharField(max_length=20, default='pending', choices=STATUS_CHOICES) 
    timestamp = models.DateTimeField(auto_now_add=True)

    provider_txn_id = models.CharField(max_length=64, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        # idempotency: one order_id per merchant
        constraints = [
            models.UniqueConstraint(fields=["merchant", "order_id"], name="uniq_merchant_order")
        ]


    def __str__(self):
        return f"payment of {self.merchant.business_name} amount is {self.amount}"
    