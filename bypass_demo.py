import requests

API_URL = "http://localhost:5000/v1/secrets"
STATIC_NHI = "STATIC_BREAK_GLASS_KEY_XYZABC"

headers = {
    "Authorization": f"Bearer {STATIC_NHI}"
}

response = requests.get(API_URL, headers=headers)
print("Status:", response.status_code)
print("Response:", response.json())