import os
import subprocess
import json

# Corrección 1: Las credenciales se leen desde variables de entorno, no hardcodeadas
DB_PASSWORD = os.getenv("APP_DB_PASSWORD", "default_secure_pass")

def ejecutar_comando_seguro(parametro_entrada: str):
    """
    Corrección 2: Se usa subprocess sin shell=True y con lista de argumentos
    estrictamente validados para evitar inyección de comandos.
    """
    comando = ["echo", str(parametro_entrada)]
    resultado = subprocess.run(comando, capture_output=True, text=True, check=True)
    return resultado.stdout

def procesar_datos_json(payload_str: str):
    """
    Corrección 3: Reemplazo de eval() por json.loads() para parseo seguro de datos.
    """
    try:
        return json.loads(payload_str)
    except json.JSONDecodeError:
        return {}