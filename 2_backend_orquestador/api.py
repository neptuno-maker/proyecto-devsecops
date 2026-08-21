from flask import Flask, jsonify
from flask_cors import CORS
import psycopg
import os

app = Flask(__name__)
CORS(app)

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "dbname": os.getenv("DB_NAME", "devsecops_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "password123")
}

def inicializar_bd():
    """Crea las tablas automáticamente si la base de datos es nueva."""
    try:
        conn = psycopg.connect(**DB_CONFIG)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS EJECUCION (
                id_ejecucion SERIAL PRIMARY KEY,
                fecha_inicio TIMESTAMP NOT NULL,
                estado_final VARCHAR(50) NOT NULL,
                commit_hash VARCHAR(100) NOT NULL
            );
            CREATE TABLE IF NOT EXISTS VULNERABILIDAD (
                id_vulnerabilidad SERIAL PRIMARY KEY,
                id_ejecucion INT REFERENCES EJECUCION(id_ejecucion) ON DELETE CASCADE,
                herramienta_origen VARCHAR(50) NOT NULL,
                tipo_vulnerabilidad TEXT NOT NULL,
                severidad VARCHAR(20) NOT NULL,
                archivo_afectado TEXT NOT NULL
            );
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("[+] Tablas de base de datos verificadas/creadas con éxito.")
    except Exception as e:
        print(f"[-] Error al inicializar tablas: {e}")

inicializar_bd()

def obtener_conexion():
    return psycopg.connect(**DB_CONFIG)

@app.route("/api/ejecuciones", methods=["GET"])
def obtener_ejecuciones():
    try:
        conn = obtener_conexion()
        cur = conn.cursor()
        cur.execute("SELECT id_ejecucion, fecha_inicio, estado_final, commit_hash FROM EJECUCION ORDER BY id_ejecucion DESC;")
        filas = cur.fetchall()
        resultado = [
            {
                "id_ejecucion": f[0],
                "fecha_inicio": f[1].strftime("%Y-%m-%d %H:%M:%S") if f[1] else None,
                "estado_final": f[2],
                "commit_hash": f[3]
            }
            for f in filas
        ]
        cur.close()
        conn.close()
        return jsonify(resultado)
    except Exception as e:
        return jsonify([]), 500

@app.route("/api/vulnerabilidades", methods=["GET"])
def obtener_vulnerabilidades():
    try:
        conn = obtener_conexion()
        cur = conn.cursor()
        cur.execute("SELECT id_vulnerabilidad, id_ejecucion, herramienta_origen, tipo_vulnerabilidad, severidad, archivo_afectado FROM VULNERABILIDAD ORDER BY id_vulnerabilidad DESC;")
        filas = cur.fetchall()
        resultado = [
            {
                "id_vulnerabilidad": f[0],
                "id_ejecucion": f[1],
                "herramienta_origen": f[2],
                "tipo_vulnerabilidad": f[3],
                "severidad": f[4],
                "archivo_afectado": f[5]
            }
            for f in filas
        ]
        cur.close()
        conn.close()
        return jsonify(resultado)
    except Exception as e:
        return jsonify([]), 500

@app.route("/api/resumen", methods=["GET"])
def obtener_resumen():
    try:
        conn = obtener_conexion()
        cur = conn.cursor()
        cur.execute("SELECT severidad, COUNT(*) FROM VULNERABILIDAD GROUP BY severidad;")
        filas = cur.fetchall()
        resumen = {"Crítica": 0, "Alta": 0, "Media": 0, "Baja": 0}
        for sev, count in filas:
            if sev in resumen:
                resumen[sev] = count
        cur.close()
        conn.close()
        return jsonify(resumen)
    except Exception as e:
        return jsonify({"Crítica": 0, "Alta": 0, "Media": 0, "Baja": 0}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)