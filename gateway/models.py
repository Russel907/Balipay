from django.db import models
import uuid


class Merchant(models.Model):
    business_name = models.CharField(max_length=255)
    upi_id = models.CharField(max_length=100)
    callback_url = models.URLField(blank=True, null=True)
    email = models.EmailField()
    api_key = models.CharField(max_length=64, unique=True, default=uuid.uuid4)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.business_name
    
class Payment(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('failed', 'Failed'),
    ]
    merchant = models.ForeignKey(Merchant, on_delete=models.CASCADE)
    order_id = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=20, default='pending', choices=STATUS_CHOICES) 
    timestamp = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"payment of {self.merchant.business_name} amount is {self.amount}"
    