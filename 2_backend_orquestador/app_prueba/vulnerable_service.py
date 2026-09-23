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

# Correccion aplicada por el desarrollador:
def consultar_sistema_inseguro(param: str):
    return subprocess.run(["ls", "-la", str(param)], capture_output=True, text=True)

import subprocess

def test_vulnerabilidad(cmd):
    # Vulnerabilidad B602 detectada por Bandit
    subprocess.run(cmd, shell=True)

def ejecutar_comando_remoto_inseguro(comando_usuario: str):
    import subprocess
    # Bandit detecta shell=True en subprocess como severidad HIGH (B602)
    return subprocess.Popen(comando_usuario, shell=True, stdout=subprocess.PIPE).communicate()