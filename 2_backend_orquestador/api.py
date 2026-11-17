from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg
import os
import jwt
import datetime

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "dbname": os.getenv("DB_NAME", "devsecops_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "password123")
}

JWT_SECRET = "devsecops_super_secret_key_2026"

def inicializar_bd():
    """Crea las tablas automáticamente si la base de datos es nueva y añade un admin por defecto."""
    try:
        conn = psycopg.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        # 1. Crear tablas
        cur.execute("""
            CREATE TABLE IF NOT EXISTS USUARIO (
                id_usuario SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL
            );
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
            CREATE TABLE IF NOT EXISTS ALERTA_NOTIFICADA (
                id_alerta SERIAL PRIMARY KEY,
                id_ejecucion INT REFERENCES EJECUCION(id_ejecucion) ON DELETE CASCADE,
                fecha_envio TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                canal_envio VARCHAR(50) NOT NULL,
                destinatario VARCHAR(100) NOT NULL
            );
        """)
        
        # 2. Crear usuario admin por defecto si no existe ninguno
        cur.execute("SELECT COUNT(*) FROM USUARIO WHERE username = 'admin';")
        if cur.fetchone()[0] == 0:
            admin_hash = generate_password_hash('admin123')
            cur.execute("INSERT INTO USUARIO (username, password_hash) VALUES (%s, %s)", ('admin', admin_hash))
            
        conn.commit()
        cur.close()
        conn.close()
        print("[+] Tablas de base de datos verificadas/creadas con éxito.")
    except Exception as e:
        print(f"[-] Error al inicializar tablas: {e}")

inicializar_bd()

def obtener_conexion():
    return psycopg.connect(**DB_CONFIG)

# --- ENDPOINTS EXISTENTES ---

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


# --- NUEVOS ENDPOINTS DE USUARIO ---

@app.route('/api/registro', methods=['POST'])
def registro():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Faltan credenciales (usuario y contraseña son obligatorios)"}), 400

    try:
        conn = obtener_conexion()
        cur = conn.cursor()
        
        # Verificar si ya existe
        cur.execute("SELECT * FROM USUARIO WHERE username = %s;", (username,))
        if cur.fetchone():
            return jsonify({"error": "El usuario ya existe"}), 400

        # Encriptar y guardar
        hashed_password = generate_password_hash(password)
        cur.execute("INSERT INTO USUARIO (username, password_hash) VALUES (%s, %s);", (username, hashed_password))
        
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"mensaje": "Usuario registrado exitosamente"}), 201
    except Exception as e:
        return jsonify({"error": f"Error interno: {str(e)}"}), 500

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')

    try:
        conn = obtener_conexion()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM USUARIO WHERE username = %s;", (username,))
        resultado = cur.fetchone()
        cur.close()
        conn.close()

        # Si el usuario existe y la contraseña encriptada coincide
        if resultado and check_password_hash(resultado[0], password):
            token = jwt.encode(
                {
                    'user': username,
                    'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=8)
                },
                JWT_SECRET,
                algorithm="HS256"
            )
            return jsonify({"token": token, "user": username}), 200
        else:
            return jsonify({"error": "Credenciales inválidas"}), 401
    except Exception as e:
        return jsonify({"error": f"Error interno: {str(e)}"}), 500

@app.route('/login', methods=['GET', 'POST'])
def login_vulnerable():
    # Simula un formulario vulnerable a falta de cabeceras CSRF y sin protección X-Frame-Options
    return """
    <html>
        <head><title>Login Inseguro</title></head>
        <body>
            <h2>Iniciar Sesión</h2>
            <form action="/login" method="post">
                <input type="text" name="user" placeholder="Usuario"><br>
                <input type="password" name="password" placeholder="Clave"><br>
                <input type="submit" value="Ingresar">
            </form>
        </body>
    </html>
    """, 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)