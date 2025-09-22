# app/serializers.py
import re
from django.contrib.auth.hashers import check_password, make_password
from rest_framework import serializers
from .models import Merchant, Payment


class MerchantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Merchant
        fields = [
            'id',
            'business_name',
            'phone_number',
            'business_type',
            'gstin',
            'business_address',
            'email',
            'password',
            'callback_url',
            'api_key',
        ]
        extra_kwargs = {
            "password": {"write_only": True}, 
            "webhook_secret": {"write_only": True}
        }

    # Email validation
    def validate_email(self, value):
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        if not re.match(email_regex, value):
            raise serializers.ValidationError("Invalid email format.")
        if Merchant.objects.filter(email=value).exists():
            raise serializers.ValidationError("A merchant with this email already exists.")
        return value

    # Phone number validation
    def validate_phone_number(self, value):
        phone_regex = r'^\+?\d{10,15}$'  # accepts 10–15 digits, optional +
        if not re.match(phone_regex, value):
            raise serializers.ValidationError("Invalid phone number format. Use digits only, optionally with +countrycode.")
        if Merchant.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("A merchant with this phone number already exists.")
        return value

    # Password validation
    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter.")
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter.")
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not re.search(r'[@$!%*?&]', value):
            raise serializers.ValidationError("Password must contain at least one special character (@$!%*?&).")
        return value

    # Callback URL validation
    def validate_callback_url(self, value):
        if value and not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("Callback URL must start with http:// or https://")
        return value

    def create(self, validated_data):
        raw_pw = validated_data.pop("password")
        validated_data["password"] = make_password(raw_pw)
        return Merchant.objects.create(**validated_data)

class MerchantLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        from .models import Merchant
        email = data.get("email")
        password = data.get("password")

        try:
            merchant = Merchant.objects.get(email=email)
        except Merchant.DoesNotExist:
            raise serializers.ValidationError("Invalid email")

        if not check_password(password, merchant.password):
            raise serializers.ValidationError("Invalid password")

        data["merchant"] = merchant
        return data


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'

    def validate(self, data):
        required_fields = ['order_id', 'amount', 'vpa']
        errors = {}

        for field in required_fields:
            if not data.get(field):
                errors[field] = f"{field.replace('_', ' ').capitalize()} is required."

        if errors:
            raise serializers.ValidationError(errors)

        return data


class PaymentHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = ['order_id', 'amount', 'status', 'timestamp']
        


class MerchantWithPaymentsSerializer(serializers.ModelSerializer):
    payments = PaymentHistorySerializer(source='payment_set', many=True)

    class Meta:
        model = Merchant
        fields = ['id', 'business_name', 'upi_id', 'email', 'api_key', 'payments']
