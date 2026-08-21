import os
import subprocess
import json

DB_PASSWORD = os.getenv("APP_DB_PASSWORD", "default_secure_pass")

def ejecutar_comando_seguro(parametro_entrada: str):
    comando = ["echo", str(parametro_entrada)]
    resultado = subprocess.run(comando, capture_output=True, text=True, check=True)
    return resultado.stdout

def procesar_datos_json(payload_str: str):
    try:
        return json.loads(payload_str)
    except json.JSONDecodeError:
        return {}

# Nueva funcion insegura para activar el Quality Gate:
def consultar_sistema_inseguro(param: str):
    return subprocess.run(f"ls -la {param}", shell=True, capture_output=True)