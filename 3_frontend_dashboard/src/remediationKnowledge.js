export const REMEDIATION_KNOWLEDGE = {
  // SAST - Bandit
  subprocess_popen_with_shell_equals_true: {
    cwe: "CWE-78: OS Command Injection",
    descripcion: "El uso de 'shell=True' permite la ejecución de comandos a través del intérprete del sistema operativo, facilitando la inyección arbitraria de código si se concatenan entradas no confiables.",
    pasos: [
      "Eliminar el parámetro 'shell=True' en subprocess.run() o subprocess.Popen().",
      "Pasar el comando y sus argumentos como una lista de cadenas separadas.",
      "Utilizar 'check=True' para manejo seguro de excepciones."
    ],
    codigoSugerido: `# Código Inseguro:
# subprocess.run(f"echo {param}", shell=True)

# Código Remediado:
import subprocess
resultado = subprocess.run(["echo", str(param)], capture_output=True, text=True, check=True)`
  },
  hardcoded_password_string: {
    cwe: "CWE-798: Use of Hard-coded Credentials",
    descripcion: "Las contraseñas o secretos incrustados en el código fuente pueden ser expuestos en repositorios de control de versiones y registros de auditoría.",
    pasos: [
      "Extraer las credenciales fuera del repositorio de código.",
      "Cargar credenciales dinámicamente mediante variables de entorno.",
      "Utilizar gestores de secretos (e.g., Vault, AWS Secrets Manager)."
    ],
    codigoSugerido: `# Código Remediado:
import os
DB_PASSWORD = os.getenv("APP_DB_PASSWORD")
if not DB_PASSWORD:
    raise ValueError("Variable de entorno APP_DB_PASSWORD no configurada.")`
  },
  blacklist: {
    cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
    descripcion: "El uso de funciones como eval() o exec() permite la ejecución no controlada de código Python arbitrario provisto por el usuario.",
    pasos: [
      "Evitar por completo el uso de eval() y exec().",
      "Para deserialización segura de cadenas estructuradas, utilizar json.loads() o ast.literal_eval()."
    ],
    codigoSugerido: `# Código Remediado:
import json
try:
    datos = json.loads(payload_str)
except json.JSONDecodeError:
    datos = {}`
  },

  // SCA - Dependencias
  sca_dependency: {
    cwe: "CWE-1104: Use of Unmaintained Third-Party Components",
    descripcion: "La dependencia contiene vulnerabilidades conocidas publicadas en la base de datos oficial CVE / PyPA, lo que permite ataques conocidos contra la versión instalada.",
    pasos: [
      "Identificar la versión parcheada recomendada por el mantenedor.",
      "Actualizar el archivo requirements.txt / package.json con la versión mínima segura.",
      "Reconstruir la imagen de contenedor o entorno virtual ejecutando pip-audit."
    ],
    codigoSugerido: `# Actualización en requirements.txt:
urllib3>=2.2.2
requests>=2.32.3
Django>=4.2.15`
  },

  // DAST - OWASP ZAP
  dast_xss: {
    cwe: "CWE-79: Cross-Site Scripting (XSS)",
    descripcion: "El endpoint refleja datos de entrada del usuario en el navegador sin adecuada codificación o sanitización contextual, permitiendo la ejecución de scripts maliciosos.",
    pasos: [
      "Sanitizar y validar exhaustivamente los parámetros de consulta y formularios.",
      "Implementar encabezados Content-Security-Policy (CSP).",
      "Utilizar plantillas con auto-escapado HTML activo."
    ],
    codigoSugerido: `# En Flask / Jinja2:
# Utilizar escape explícito si se procesa HTML manualmente:
from markupsafe import escape
@app.route("/login")
def login():
    user = escape(request.args.get("user", ""))
    return render_template("login.html", user=user)`
  }
};

export function obtenerGuiaRemediacion(vulnerabilidad) {
  const tipo = vulnerabilidad.tipo_vulnerabilidad.toLowerCase();
  const origen = vulnerabilidad.herramienta_origen.toLowerCase();

  if (origen.includes("sca")) {
    return REMEDIATION_KNOWLEDGE.sca_dependency;
  }
  if (tipo.includes("shell") || tipo.includes("subprocess")) {
    return REMEDIATION_KNOWLEDGE.subprocess_popen_with_shell_equals_true;
  }
  if (tipo.includes("password") || tipo.includes("hardcoded")) {
    return REMEDIATION_KNOWLEDGE.hardcoded_password_string;
  }
  if (tipo.includes("eval") || tipo.includes("blacklist")) {
    return REMEDIATION_KNOWLEDGE.blacklist;
  }
  if (origen.includes("dast") || tipo.includes("xss")) {
    return REMEDIATION_KNOWLEDGE.dast_xss;
  }

  return {
    cwe: "CWE-699: Software Development Security Vulnerability",
    descripcion: "Vulnerabilidad detectada durante el escaneo automatizado del pipeline.",
    pasos: [
      "Revisar el archivo afectado en la línea señalada.",
      "Consultar la documentación oficial de la herramienta de escaneo.",
      "Aplicar el principio de menor privilegio y validación estricta de entradas."
    ],
    codigoSugerido: `# Consulte la guía de seguridad interna para remediar ${vulnerabilidad.archivo_afectado}`
  };
}