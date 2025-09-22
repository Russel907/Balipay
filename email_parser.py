import imaplib
import email
import re
import django
import os
import sys
import time

# Setup Django environment
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "balipay.settings")
django.setup()

from gateway.models import Payment

# Email configuration
IMAP_SERVER = 'imap.gmail.com'
EMAIL_ACCOUNT = 'fairoosa02112000@gmail.com'
EMAIL_PASSWORD = 'fqrh xapz jrtq cjrr'

# UPI email senders and patterns
UPI_SENDERS = [
    "alerts@hdfcbank.com",
    "noreply@paytm.com",
    "alerts@icicibank.com",
    "UPI@axisbank.com",
    "noreply@phonepe.com",
    "noreply@google.com",
    "kaiztrensubscription@gmail.com",
    "kaiztren@gmail.com"
]

UPI_ID_PATTERN = r'[\w\.-]+@[\w\.-]+'
AMOUNT_PATTERN = r'₹\s?(\d+(?:\.\d{1,2})?)'

def check_emails():
    try:
        # Connect to IMAP
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, EMAIL_PASSWORD)
        mail.select('inbox')

        for sender in UPI_SENDERS:
            status, messages = mail.search(None, f'FROM "{sender}"')
            if status != "OK":
                print(f"❌ Could not fetch emails from {sender}")
                continue

            for num in messages[0].split():
                typ, data = mail.fetch(num, "(RFC822)")
                msg = email.message_from_bytes(data[0][1])
                subject = msg.get("Subject", "")
                print(f"\n📩 Processing email: {subject}")

                # Extract body
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))
                        if content_type == "text/plain" and "attachment" not in content_disposition:
                            body = part.get_payload(decode=True).decode(errors="ignore")
                            break
                else:
                    body = msg.get_payload(decode=True).decode(errors="ignore")

                print("✉️ Body Preview:", body[:200])

                # Extract UPI ID & amount
                upi_matches = re.findall(UPI_ID_PATTERN, body)
                amount_matches = re.findall(AMOUNT_PATTERN, body)

                if not upi_matches or not amount_matches:
                    print("⚠️ No UPI ID or Amount found — skipping email.")
                    continue

                upi_id = upi_matches[0]
                amount = float(amount_matches[0])
                print(f"🔍 Found UPI ID: {upi_id}, Amount: {amount}")

                payments = Payment.objects.filter(status="pending", amount=amount)

                updated = False
                for payment in payments:
                    if payment.merchant.upi_id.lower() == upi_id.lower():
                        payment.status = "paid"
                        payment.save()
                        print(f"✅ Updated payment {payment.order_id} to PAID.")
                        updated = True
                        break

                if not updated:
                    print("❌ No matching payment found for this UPI transaction.")

        mail.logout()
        print("✅ Email check complete.")

    except Exception as e:
        print(f"💥 Error: {e}")

# Run every 300 seconds
if __name__ == "__main__":
    while True:
        print("\n⏰ Checking emails for UPI payments...")
        check_emails()
        print("⏳ Sleeping for 300 seconds...\n")
        time.sleep(300)
