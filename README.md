# Plataforma Automatizada DevSecOps & Quality Gate

[![Pipeline DevSecOps & Quality Gate](https://github.com/neptuno-maker/proyecto-devsecops/actions/workflows/devsecops-pipeline.yml/badge.svg)](https://github.com/neptuno-maker/proyecto-devsecops/actions/workflows/devsecops-pipeline.yml)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL%2015-316192?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Python](https://img.shields.io/badge/Orchestrator-Python%203.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![React](https://img.shields.io/badge/Dashboard-React%20%2B%20Vite-61DAFB?logo=react&logoColor=black)](https://reactjs.org/)

Plataforma integral de seguridad continua (DevSecOps) diseñada para auditar, persistir y visualizar el estado de seguridad del código fuente y sus dependencias en un ciclo de Integración Continua (CI/CD).

---

## Arquitectura del Sistema

```text
[ Git Push / PR ]
       │
       ▼
[ GitHub Actions Runner ]
├── 1. SAST Engine (Bandit) ───────> [ CWE / Inyecciones ]
├── 2. SCA Engine (pip-audit) ────> [ CVE / Vulnerabilidades ]
├── 3. Quality Gate Evaluator ────> [ Bloqueo / Aprobación ]
└── 4. PostgreSQL (Persistencia) ──> [ Histórico de Auditorías ]
       │
       ▼
[ Frontend Dashboard (React) ] ─────> [ Métricas, Filtros, Exportación PDF/CSV ]
```
---

## Capacidades Principales

Análisis SAST (Static Application Security Testing): Detección estática de vulnerabilidades en código Python mediante Bandit.

Análisis SCA (Software Composition Analysis): Identificación automatizada de vulnerabilidades y exposiciones conocidas (CVE) en librerías externas mediante pip-audit.

Quality Gate Automatizado: Evaluación basada en severidad. Si existen fallos de severidad HIGH o CRITICAL, el runner emite código de salida de error (exit 1) bloqueando Pull Requests automáticamente.

Persistencia Relacional: Almacenamiento estructurado de auditorías y hallazgos en base de datos PostgreSQL.

Dashboard Interactivo: Panel de visualización con métricas, gráficos reactivos, asistente de remediación contextual y exportación a PDF/CSV.

---

## Estructura del Repositorio

├── .github/workflows/
│   └── devsecops-pipeline.yml     # Flujo CI/CD automatizado en GitHub Actions
├── 1_infraestructura/
│   ├── docker-compose.yml         # Contenedores de base de datos y orquestación
│   └── init_db.sql                # Esquema de tablas relacionales
├── 2_backend_orquestador/
│   ├── app_prueba/                # Código de prueba para análisis de seguridad
│   ├── orquestador.py             # Motor de análisis SAST, SCA y Quality Gate
│   ├── api.py                     # API REST para alimentar el Dashboard
│   └── requirements.txt           # Librerías y dependencias del backend
├── 3_frontend_dashboard/
│   ├── src/                       # Aplicación React (métricas, gráficos, modales)
│   └── package.json               # Dependencias del cliente web
└── README.md                      # Documentación del proyecto

