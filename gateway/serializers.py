from rest_framework import serializers
from django.contrib.auth.hashers import check_password
from decimal import Decimal, InvalidOperation
from django.core.validators import RegexValidator
from django.utils import timezone
from rest_framework.authtoken.models import Token
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from .models import Merchant, Payment, ENTITY_TYPE_CHOICES, OTP, APIKey
from django.contrib.auth import get_user_model
User = get_user_model()


phone_validator = RegexValidator(r'^\+?\d{7,15}$', 'Enter a valid phone number (7-15 digits, optional +).')
pincode_validator = RegexValidator(r'^\d{4,6}$', 'Enter a valid pincode (4-6 digits).')


class MerchantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Merchant
        fields = [
            "id",
            "webhook_secret",
            "gst_file",
            "pan_file",
            "signatory_file",
            "is_active",
            "created_at",
            "updated_at",
            "gst_file",
            "pan_file",
            "signatory_file"
            # ❌ no "token" here
        ]


class MerchantSignupSerializer(serializers.ModelSerializer):
    phone_number = serializers.CharField(validators=[phone_validator])
    pincode = serializers.CharField(required=False, allow_blank=True, validators=[pincode_validator])
    entity_type = serializers.ChoiceField(choices=ENTITY_TYPE_CHOICES)
    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True, min_length=8)
    gst_file = serializers.FileField(required=False)
    pan_file = serializers.FileField(required=False)
    signatory_file = serializers.FileField(required=False)

    class Meta:
        model = Merchant
        fields = [
            "business_name",
            "contact_name",
            "phone_number",
            "entity_type",
            "business_address",
            "pincode",
            "email",
            "password",
            "gst_file",
            "pan_file",
            "signatory_file",
        ]

    def validate_email(self, value):
        """Ensure no user already exists with this email"""
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def create(self, validated_data):
        # Extract user-related fields
        email = validated_data.pop("email")
        password = validated_data.pop("password")

        # Create the Django User
        user = User.objects.create_user(username=email, email=email, password=password)

        # Create the Merchant profile linked to this user
        merchant = Merchant.objects.create(
            user=user,
            business_name=validated_data.get("business_name", ""),
            contact_name=validated_data["contact_name"],
            phone_number=validated_data["phone_number"],
            entity_type=validated_data.get("entity_type"),
            business_address=validated_data.get("business_address", ""),
            pincode=validated_data.get("pincode", ""),
            gst_file=validated_data.get("gst_file"),
            pan_file=validated_data.get("pan_file"),
            signatory_file=validated_data.get("signatory_file"),
            is_active=False,
        )

        # Automatically create a DRF token for authentication
        token, _ = Token.objects.get_or_create(user=user)
        merchant.token = token.key  # store for serializer representation
        return merchant

    def to_representation(self, instance):
        """Customize response to include token and email"""
        rep = super().to_representation(instance)
        rep["email"] = instance.user.email
        rep["token"] = instance.token
        rep["gst"] = instance.gst_file
        rep["pan"]= instance.pan_file
        rep["signatory"] = instance.signatory_file
        return rep


class MerchantLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        user = authenticate(username=email, password=password)
        if user is None:
            raise serializers.ValidationError({"detail": "Invalid email or password."})
        try:
            merchant = user.merchant_profile 
        except Merchant.DoesNotExist:
            raise serializers.ValidationError({"detail": "No merchant profile found for this account."})

        attrs["user"] = user
        attrs["merchant"] = merchant
        return attrs


class MerchantProfileUpdateSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source="user.email", required=False)

    class Meta:
        model = Merchant
        fields = [
            "business_name",
            "contact_name",
            "phone_number",
            "business_address",
            "pincode",
            "gst_file",
            "pan_file",
            "signatory_file",
            "email",
        ]
        read_only_fields = ["phone_number"]  # set files read-only if you handle them specially

    def update(self, instance, validated_data):
        user_data = validated_data.pop("user", None)
        if user_data:
            new_email = user_data.get("email")
            if new_email and new_email.lower() != instance.user.email.lower():
                if User.objects.filter(email__iexact=new_email).exists():
                    raise serializers.ValidationError({"email": "Email already in use."})
                instance.user.email = new_email
                instance.user.username = new_email  # if you use email as username
                instance.user.save(update_fields=["email", "username"])
                # optionally mark email as unverified here and trigger verification

        for attr, val in validated_data.items():
            setattr(instance, attr, val)
        instance.save()
        return instance


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        return value


class ForgotPasswordConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    def validate_otp_code(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("OTP must be six digit")
        return value

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "passwords do not match."})
        return attrs


class SendOTPSerializer(serializers.Serializer):
    purpose = serializers.CharField(required=False, allow_blank=True)


class VerifyOTPSerializer(serializers.Serializer):
    otp_id = serializers.IntegerField(required=False)
    otp_code = serializers.CharField(max_length=6)

    def validate_otp_code(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("OTP must be 6 digits.")
        return value


class GenerateAPIKeySerializer(serializers.Serializer):
    name = serializers.CharField(required=False, allow_blank=True, max_length=255)
    mode = serializers.ChoiceField(choices=("test", "live"), default="test")
    ttl_seconds = serializers.IntegerField(required=False, allow_null=True, min_value=1)


class APIKeyListSerializer(serializers.ModelSerializer):
    masked_secret = serializers.SerializerMethodField()

    class Meta:
        model = APIKey
        fields = ("id", "key_id", "name", "mode", "created_at", "expires_at", "revoked", "last_used_at", "masked_secret")

    def get_masked_secret(self, obj):
        return f"{obj.key_id} ••••••••"


class PaymentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Payment
        fields = '__all__'
        read_only_fields = [
            'status',
            'provider_order_id',
            'provider_payment_id',
            'provider_order_response',
            'provider_payment_response',
            'amount_in_paise',
            'currency',
            'idempotency_key',
            'attempts',
            'created_at',
            'updated_at',
            'paid_at',
            'cancelled_at',
        ]
        
    def validate_amount(self, value):
        try:
            # Accept string or numeric, ensure two decimal places
            Decimal(str(value))
        except Exception:
            raise serializers.ValidationError("Invalid amount")
        return value
