import psycopg
import datetime
import requests
import json
import subprocess
import os
import sys

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "devsecops_db",
    "user": "postgres",
    "password": "password123"
}

WEBHOOK_URL = "https://webhook.site/1407f885-217b-466b-874a-ee5681e30e8f"

def ejecutar_escaneo_sast_real(ruta_analizar="app_prueba"):
    """Ejecuta Bandit (SAST) sobre el código fuente."""
    print(f"[*] Ejecutando análisis SAST (Bandit) sobre: {ruta_analizar}...")
    try:
        resultado = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", ruta_analizar, "-f", "json"],
            capture_output=True,
            text=True
        )
        data = json.loads(resultado.stdout)
        
        hallazgos_sast = []
        for issue in data.get("results", []):
            sev_map = {"HIGH": "Crítica", "MEDIUM": "Alta", "LOW": "Baja"}
            severidad = sev_map.get(issue.get("issue_severity"), "Baja")
            
            hallazgos_sast.append({
                "origen": "SAST (Bandit)",
                "tipo": f"{issue.get('test_name')}: {issue.get('issue_text')}",
                "severidad": severidad,
                "archivo": f"{issue.get('filename')}:{issue.get('line_number')}"
            })
        return hallazgos_sast
    except Exception as e:
        print(f"[-] Error al ejecutar Bandit: {e}")
        return []

def ejecutar_escaneo_sca_real(archivo_req="app_prueba/requirements_vulnerable.txt"):
    """Ejecuta pip-audit (SCA) sobre las dependencias del proyecto."""
    print(f"[*] Ejecutando análisis SCA (pip-audit) sobre: {archivo_req}...")
    if not os.path.exists(archivo_req):
        print(f"[!] No se encontró el archivo de requerimientos: {archivo_req}")
        return []

    try:
        resultado = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-r", archivo_req, "-f", "json"],
            capture_output=True,
            text=True
        )
        salida_json = resultado.stdout if resultado.stdout else resultado.stderr
        data = json.loads(salida_json)
        
        hallazgos_sca = []
        for pkg in data.get("dependencies", []):
            for vuln in pkg.get("vulns", []):
                hallazgos_sca.append({
                    "origen": "SCA (pip-audit)",
                    "tipo": f"Dependencia vulnerable [{pkg.get('name')}@{pkg.get('version')}]: {vuln.get('id')}",
                    "severidad": "Alta",
                    "archivo": f"{archivo_req} -> {pkg.get('name')}"
                })
        return hallazgos_sca
    except Exception as e:
        print(f"[-] Error al ejecutar pip-audit: {e}")
        return []

def leer_reporte_dast_real(ruta_reporte="dast_report.json"):
    """Lee y parsea el reporte JSON generado por OWASP ZAP."""
    print(f"[*] Verificando reporte DAST (OWASP ZAP) en: {ruta_reporte}...")
    if not os.path.exists(ruta_reporte):
        # Fallback a directorio zap_report si no fue movido a la raíz
        ruta_alt = os.path.join("zap_report", "dast_report.json")
        if os.path.exists(ruta_alt):
            ruta_reporte = ruta_alt
        else:
            print("[i] No se encontró reporte DAST dinámico. Se asume sin hallazgos DAST.")
            return []

    try:
        with open(ruta_reporte, "r", encoding="utf-8") as f:
            data = json.load(f)

        hallazgos_dast = []
        # El formato JSON de OWASP ZAP estructura las alertas dentro de 'site' -> 'alerts'
        sitios = data.get("site", [])
        if isinstance(sitios, dict):
            sitios = [sitios]

        sev_map = {"3": "Alta", "2": "Media", "1": "Baja", "0": "Informativa"}

        for site in sitios:
            for alert in site.get("alerts", []):
                risk_code = str(alert.get("riskcode", "1"))
                severidad = sev_map.get(risk_code, "Baja")
                
                # Extraer la URL o endpoint evaluado
                instances = alert.get("instances", [])
                uri = instances[0].get("uri") if instances else site.get("@name", "/endpoint")

                hallazgos_dast.append({
                    "origen": "DAST (OWASP ZAP)",
                    "tipo": f"{alert.get('alert')}: {alert.get('name', '')}",
                    "severidad": severidad,
                    "archivo": uri
                })

        print(f"[+] DAST procesado: {len(hallazgos_dast)} alertas extraídas de OWASP ZAP.")
        return hallazgos_dast
    except Exception as e:
        print(f"[-] Error al parsear reporte DAST de ZAP: {e}")
        return []

def enviar_notificacion_webhook(id_ejecucion, commit_hash, total_fallos, hallazgos):
    payload = {
        "evento": "PIPELINE_QUALITY_GATE_FAILED",
        "timestamp": datetime.datetime.now().isoformat(),
        "id_ejecucion": id_ejecucion,
        "commit": commit_hash,
        "alerta": f"ALERTA DEVSECOPS: Despliegue bloqueado. Se detectaron {total_fallos} fallos críticos/altos.",
        "detalles": [h for h in hallazgos if h["severidad"] in ["Crítica", "Alta"]]
    }
    try:
        if WEBHOOK_URL and "http" in WEBHOOK_URL:
            requests.post(WEBHOOK_URL, json=payload, headers={"Content-Type": "application/json"}, timeout=5)
            print("[+] Notificación Webhook enviada al canal de alertas.")
    except Exception as e:
        print(f"[-] Error al enviar Webhook: {e}")

def ejecutar_pipeline(commit_hash=None):
    if commit_hash is None:
        commit_hash = os.getenv("COMMIT_HASH", "manual_devsecops_scan")

    print("=" * 60)
    print(f"[*] INICIANDO PIPELINE DEVSECOPS - COMMIT: {commit_hash}")
    print("=" * 60)

    try:
        conn = psycopg.connect(**DB_CONFIG)
        cur = conn.cursor()
        print("[+] Conexión exitosa con PostgreSQL.")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS EJECUCION (
                id_ejecucion SERIAL PRIMARY KEY,
                fecha_inicio TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                estado_final VARCHAR(50) NOT NULL,
                commit_hash TEXT
            );
            CREATE TABLE IF NOT EXISTS VULNERABILIDAD (
                id_vulnerabilidad SERIAL PRIMARY KEY,
                id_ejecucion INT REFERENCES EJECUCION(id_ejecucion) ON DELETE CASCADE,
                herramienta_origen VARCHAR(50) NOT NULL,
                tipo_vulnerabilidad TEXT NOT NULL,
                severidad VARCHAR(50) NOT NULL,
                archivo_afectado TEXT
            );
            ALTER TABLE VULNERABILIDAD ALTER COLUMN tipo_vulnerabilidad TYPE TEXT;
            ALTER TABLE VULNERABILIDAD ALTER COLUMN archivo_afectado TYPE TEXT;
        """)
        
        conn.commit()
        print("[+] Esquema de base de datos verificado/creado.")
    except Exception as e:
        print(f"[-] Error al conectar con la base de datos: {e}")
        return

    # 1. Registrar Ejecución
    cur.execute(
        "INSERT INTO EJECUCION (fecha_inicio, estado_final, commit_hash) VALUES (%s, %s, %s) RETURNING id_ejecucion;",
        (datetime.datetime.now(), "En Proceso", commit_hash)
    )
    id_ejecucion = cur.fetchone()[0]
    conn.commit()

    # 2. Ejecutar escaneos (SAST + SCA + DAST real)
    sast_hallazgos = ejecutar_escaneo_sast_real("app_prueba")
    sca_hallazgos = ejecutar_escaneo_sca_real("app_prueba/requirements_vulnerable.txt")
    dast_hallazgos = leer_reporte_dast_real("dast_report.json")

    todos = sast_hallazgos + sca_hallazgos + dast_hallazgos
    contador_criticas_altas = 0

    # 3. Guardar en PostgreSQL
    for v in todos:
        if v["severidad"] in ["Crítica", "Alta"]:
            contador_criticas_altas += 1
        cur.execute(
            """INSERT INTO VULNERABILIDAD (id_ejecucion, herramienta_origen, tipo_vulnerabilidad, severidad, archivo_afectado) 
               VALUES (%s, %s, %s, %s, %s);""",
            (id_ejecucion, v["origen"], v["tipo"], v["severidad"], v["archivo"])
        )
    conn.commit()
    print(f"[+] Se almacenaron {len(todos)} vulnerabilidades detectadas en la base de datos.")

    # 4. Evaluación Quality Gate
    if contador_criticas_altas > 0:
        estado_final = "Bloqueado"
        print(f"\n[!] Quality Gate: BLOQUEADO ({contador_criticas_altas} fallos severos detectados).")
        enviar_notificacion_webhook(id_ejecucion, commit_hash, contador_criticas_altas, todos)
    else:
        estado_final = "Aprobado"
        print("\n[V] Quality Gate: APROBADO (0 vulnerabilidades críticas/altas encontradas). Despliegue permitido.")

    # 5. Cierre
    cur.execute("UPDATE EJECUCION SET estado_final = %s WHERE id_ejecucion = %s;", (estado_final, id_ejecucion))
    conn.commit()
    cur.close()
    conn.close()
    print("[+] Pipeline completado exitosamente.\n")

    if estado_final == "Bloqueado":
        sys.exit(1)

if __name__ == "__main__":
    ejecutar_pipeline()