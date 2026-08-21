# Plataforma Automatizada de Quality Gate y Pipeline DevSecOps

Este proyecto implementa una solución integral de DevSecOps orientada a la seguridad continua en el ciclo de vida del software (CI/CD). Automatiza la ejecución de análisis estático (SAST) y dinámico (DAST), evalúa políticas de bloqueo basadas en severidad y centraliza métricas mediante una base de datos relacional y un dashboard en tiempo real.

---

## Arquitectura del Sistema

El sistema está dividido en tres capas desacopladas:

1. **Infraestructura (`1_infraestructura`):**
   - Base de datos relacional **PostgreSQL 15** desplegada en contenedor Docker.
   - Persistencia de datos mediante volúmenes Docker (`db_data`).
   - Esquema normalizado compuesto por las entidades `EJECUCION`, `VULNERABILIDAD` y `ALERTA_NOTIFICADA`.

2. **Backend & Orquestador (`2_backend_orquestador`):**
   - **Orquestador DevSecOps (`orquestador.py`):** Ejecuta escaneos reales con el analizador estático **Bandit**, simula pruebas dinámicas (DAST), audita el Quality Gate y despacha webhooks ante eventos críticos.
   - **API REST (`api.py`):** Servicio web construido en **Flask** con soporte CORS que expone endpoints JSON (`/api/resumen`, `/api/ejecuciones`, `/api/vulnerabilidades`).

3. **Frontend Dashboard (`3_frontend_dashboard`):**
   - Interfaz gráfica moderna construida con **React** y **Vite**.
   - Visualización analítica interactiva mediante **Recharts** (distribución de severidad y comparativa SAST vs. DAST).
   - Historial de ejecuciones y trazabilidad de commits en vivo.

---

## Política de Quality Gate

- **Criterio de Bloqueo:** Si el pipeline detecta $\ge 1$ vulnerabilidad de severidad **Crítica** o **Alta**, el despliegue a producción se bloquea inmediatamente.
- **Notificación Automática:** Ante cualquier bloqueo, se emite un payload HTTP POST estructurado vía Webhook con el detalle de los archivos afectados y tipos de fallo (CWE).
- **Criterio de Aprobación:** Únicamente se autoriza el despliegue cuando los fallos detectados son de severidad Media, Baja o Inexistentes.

---

## Guía de Despliegue Local

### 1. Iniciar Base de Datos (Docker)
```bash
cd 1_infraestructura
docker compose up -d