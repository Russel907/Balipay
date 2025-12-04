import requests
from django.conf import settings

def ocr_extract_text(image_file):
    url = settings.OCR_SPACE_URL
    api_key = settings.OCR_SPACE_API_KEY

    payload = {
        'language': 'eng',
        'isOverlayRequired': False
    }

    files = {
        'file': (image_file.name, image_file.read())
    }

    headers = {
        'apikey': api_key
    }

    response = requests.post(url, data=payload, files=files, headers=headers)

    try:
        return response.json()
    except:
        return {"error": "Invalid OCR response"}
