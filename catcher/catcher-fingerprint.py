# My custom catcher to validate Fingerprint Spoofing and IP Rotation from Github Actions
import os
import logging
import json
from datetime import datetime
from colorama import Fore, Style
from flask import Flask, request, jsonify


# --- 1. INSTÂNCIA DO FLASK (Correção do NameError) ---
app = Flask(__name__)

# --- 2. Configuração de Logging ---
log_directory = "output"
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(filename=os.path.join(log_directory, 'full.log'),
                    level=logging.INFO,
                    format='[%(asctime)s %(levelname)s] %(message)s')

def log_message(message, color=None):
    """Imprime a mensagem no console com timestamp e cor, e a registra no arquivo de log."""
    timestamp = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    if color:
        print(f"[{timestamp}] {color}{message}{Style.RESET_ALL}")
    else:
        print(f"[{timestamp}] {message}")

    logging.info(f"{message}")


# --- 3. Rota Principal ---
@app.route("/wow-amazing", methods=["POST"])
def handle_post_data():
    try:
        # Tenta obter o JSON principal (que contém a lista de resultados)
        data = request.get_json()

        log_message("[+] Received Data from client:", color=Fore.GREEN)

        # Verifica se o formato esperado (lista com dicionário e chave 'response') está presente
        if isinstance(data, list) and data and "response" in data[0]:

            # Pega a string JSON completa da resposta da URL de teste
            response_json_string = data[0]["response"]

            try:
                # Carrega a string JSON da API de teste (o valor de 'response')
                response_data = json.loads(response_json_string)

                # --- LÓGICA DE EXTRAÇÃO ANINHADA ---

                # 1. IP (Está no nível raiz, remove a porta se estiver presente)
                full_ip_port = response_data.get("ip", "N/A")
                ip = full_ip_port.split(':')[0]

                # 2. JA4 (Estão dentro do objeto 'tls')
                tls_data = response_data.get("tls", {})

                ja4 = tls_data.get("ja4", "N/A")

                # --- FIM DA LÓGICA DE EXTRAÇÃO ---

                # 3. Loga os valores extraídos
                log_message("--- EXTRACTED FINGERPRINT DATA ---", color=Fore.CYAN)
                log_message(f"IP: {ip}")
                log_message(f"JA4: {ja4}")
                log_message("------------------------------------", color=Fore.CYAN)

                logging.info(f"EXTRACTED: IP={ip}, JA4={ja4}")

            except json.JSONDecodeError:
                # Se a string em "response" não for um JSON válido (ex: erro 500 ou HTML)
                log_message("[!] Response is not valid JSON (e.g., error 500 or HTML).", color=Fore.RED)
                logging.error(f"Invalid JSON Body: {response_json_string[:200]}...")

        else:
            log_message("[!] Received data is not in expected list/response format.", color=Fore.YELLOW)

        return jsonify({"status": "success", "message": "Data received and fingerprint extracted"}), 200

    except Exception as e:
        log_message(f"[!] Critical Error handling request: {str(e)}", color=Fore.RED)
        return jsonify({"error": str(e)}), 500


# --- 4. Execução Principal ---
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=20005)
