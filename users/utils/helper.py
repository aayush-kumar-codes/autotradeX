import requests, re

def validate_binance_keys(api_key, secret_key):
    url = 'https://api.binance.com/api/v3/account'
    headers = {
        'X-MBX-APIKEY': api_key
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return True
    else:
        return False
    
def validate_telegram(telegram):
    if not re.match(r'^@[A-Za-z0-9_]+$', telegram):
        return False
    return True

def validate_password(password, confirm_password):
    print(password, confirm_password)
    if password != confirm_password:
        return "Passwords do not match."

    if len(password) < 8:
        return "Password must be 8 characters long."

    if not re.search(r'\d', password):
        return "Password must be one digit."

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return "Password must be one special character."

    return None