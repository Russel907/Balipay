from django.contrib import admin
from .models import Payment, Merchant, OTP, APIKey, Refund


admin.site.register(Payment)
admin.site.register(Merchant)
admin.site.register(OTP)
admin.site.register(APIKey)
admin.site.register(Refund)
