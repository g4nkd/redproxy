# request to verify ip and some fingerprint 
import requests
import os
from urllib3.exceptions import InsecureRequestWarning

required_env_vars = ["CATCHERURL", "CATCHERTLS"]
missing_env_vars = [var for var in required_env_vars if os.getenv(var) is None]

if missing_env_vars:
    missing_vars_str = ", ".join(missing_env_vars)
    raise ValueError(f"Missing environment variables: {missing_vars_str}")

# TODO: add target and other data here later to make this more modular
# Fetch environment variables
catcher_URL = os.getenv("CATCHERURL")
catcher_uses_TLS_str = os.getenv("CATCHERTLS")
# Convert catcher_uses_TLS_str to boolean
catcher_uses_TLS = catcher_uses_TLS_str.lower() == "true"

def send_login_request():
    url = "https://tls.peet.ws/api/all"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36.",
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            proxies={"https": "http://changeme:changeme@127.0.0.1:1234"},
            timeout=5,
            verify=False
        )
        return response.status_code, response.text

    except requests.RequestException:
        return None, None

def send_data_to_catcher(data, use_ssl):
    """Envia os resultados para o Catcher URL usando POST e JSON."""
    if not use_ssl:
        # ATENÇÃO: Desabilitar avisos de SSL (InsecureRequestWarning) é um risco de segurança.
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    try:
        # CORREÇÃO: Usando requests.post e enviando os dados como JSON
        response = requests.post(catcher_URL, json=data, timeout=3, verify=use_ssl)
        response.raise_for_status() # Lança exceção para códigos de erro HTTP
        print(f"[+] Data sent to the catcher. Status: {response.status_code}")
    except requests.RequestException as e:
        print(f"[-] Failed to send data to the catcher. Error: {e}")
        
# Initialize an empty list to store results
results = []

# CORREÇÃO: Inicializa o dicionário 'result' antes de usá-lo
result = {}

# Perform the login request
login_response_code, login_response = send_login_request()
if login_response_code is not None and login_response is not None:
    result["status_code"] = login_response_code
    result["response"] = login_response
else:
    result["status_code"] = 500
    result["response"] = "Github actions workflow failed to perform login request"
results.append(result)

# Send all results to the catcher
send_data_to_catcher(results, use_ssl=catcher_uses_TLS)
