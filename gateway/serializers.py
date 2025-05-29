# app/serializers.py
import re
from rest_framework import serializers
from .models import Merchant, Payment

class MerchantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Merchant
        fields = ['id','business_name', 'upi_id', 'email', 'callback_url','api_key'] 

    def validate_email(self, value):
        print("email:", value)
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, value):
            raise serializers.ValidationError("Invalid email format.")
        if Merchant.objects.filter(email=value).exists():
            raise serializers.ValidationError("A merchant with this email already exists.")
        return value

    def validate_callback_url(self, value):
        if value and not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("Callback URL must start with http:// or https://")
        return value
    

class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'


class PaymentHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['order_id', 'amount', 'status', 'timestamp']
        


class MerchantWithPaymentsSerializer(serializers.ModelSerializer):
    payments = PaymentHistorySerializer(source='payment_set', many=True)

    class Meta:
        model = Merchant
        fields = ['id', 'business_name', 'upi_id', 'email', 'api_key', 'payments']
