import requests

PAN_URL = "https://pan-veification.p.rapidapi.com/Panbasic"

PAN_HEADERS = {
    "Content-Type": "application/json",
    "X-RapidAPI-Key": "f5a32c75demshfc32c07e06f429cp1c3813jsn549c033cab7d",
    "X-RapidAPI-Host": "pan-veification.p.rapidapi.com"
}

def verify_pan(pan_number):
    payload = {"pan": pan_number}
    
    try:
        res = requests.post(PAN_URL, json=payload, headers=PAN_HEADERS)
        return safe_json(res)
    except Exception as e:
        return {"error": str(e)}

def safe_json(res):
    try:
        return res.json()
    except:
        return {"status": res.status_code, "text": res.text}
GST_URL = "https://gst-verification2.p.rapidapi.com/GST/Gstverify"

GST_HEADERS = {
    "Content-Type": "application/json",
    "X-RapidAPI-Key": "f5a32c75demshfc32c07e06f429cp1c3813jsn549c033cab7d",
    "X-RapidAPI-Host": "gst-verification2.p.rapidapi.com"
}


def verify_gst(gstnumber):
    payload = {
        "gstnumber": gstnumber,
        "consent": "Y",
        "consent_text": "I agree to fetch my GST information for verification."
    }

    try:
        res = requests.post(GST_URL, json=payload, headers=GST_HEADERS)
        return safe_json(res)
    except Exception as e:
        return {"error": str(e)}

def get_gst_signatory(gstnumber):
    payload = {
        "gstnumber": gstnumber,
        "consent": "Y",
        "consent_text": "I agree to fetch GST signatory details."
    }

    try:
        res = requests.post(GST_URL, json=payload, headers=GST_HEADERS)
        data = safe_json(res)
        return data
    except Exception as e:
        return {"error": str(e)}
