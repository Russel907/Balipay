from cryptography.fernet import Fernet
from django.conf import settings


def get_fernet():
    key = settings.ENCRYPTION_KEY.encode()
    return Fernet(key)


def encrypt_value(plain_text: str) -> str:
    f = get_fernet()
    token = f.encrypt(plain_text.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_value(token: str) -> str:
    f = get_fernet()
    plain = f.decrypt(token.encode("utf-8"))
    return plain.decode("utf-8")
