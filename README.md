# Plataforma Automatizada DevSecOps & Quality Gate

[![Pipeline DevSecOps & Quality Gate](https://github.com/neptuno-maker/proyecto-devsecops/actions/workflows/devsecops-pipeline.yml/badge.svg)](https://github.com/neptuno-maker/proyecto-devsecops/actions/workflows/devsecops-pipeline.yml)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL%2015-316192?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Python](https://img.shields.io/badge/Orchestrator-Python%203.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![React](https://img.shields.io/badge/Dashboard-React%20%2B%20Tailwind-61DAFB?logo=react&logoColor=black)](https://reactjs.org/)

Plataforma integral de seguridad continua (DevSecOps) diseñada para auditar, persistir y visualizar el estado de seguridad del código fuente y sus dependencias en un ciclo de Integración Continua (CI/CD).

---

## Arquitectura del Sistema

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

---

## Capacidades Principales

* **Análisis SAST (Static Application Security Testing):** Detección estática de vulnerabilidades en código Python mediante Bandit.
* **Análisis SCA (Software Composition Analysis):** Identificación automatizada de vulnerabilidades y exposiciones conocidas (CVE) en librerías externas mediante `pip-audit`.
* **Quality Gate Automatizado:** Evaluación basada en severidad. Si existen fallos de severidad **HIGH** o **CRITICAL**, el runner emite código de salida de error (`exit 1`) bloqueando Pull Requests automáticamente.
* **Persistencia Relacional:** Almacenamiento estructurado de auditorías y hallazgos en base de datos PostgreSQL 15.
* **Dashboard Interactivo:** Panel de visualización con métricas, gráficos reactivos, asistente de remediación contextual y exportación a PDF/CSV.

---

## Estructura del Repositorio

├── .github/workflows/
│   └── devsecops-pipeline.yml     # Flujo CI/CD automatizado en GitHub Actions
├── 1_infraestructura/
│   ├── docker-compose.yml         # Contenedores de base de datos y orquestacion
│   └── init.sql                   # Esquema de tablas relacionales
├── 2_backend_orquestador/
│   ├── app_prueba/                # Codigo de prueba para analisis de seguridad
│   ├── orquestador.py             # Motor de analisis SAST, SCA y Quality Gate
│   ├── api.py                     # API REST para alimentar el Dashboard
│   └── requirements.txt           # Librerias y dependencias del backend
├── 3_frontend_dashboard/
│   ├── src/                       # Aplicacion React (metricas, graficos, modales)
│   └── package.json               # Dependencias del cliente web
└── README.md                      # Documentacion del proyecto

---

## Estructura del Repositorio

1. Iniciar Base de Datos

cd 1_infraestructura
docker compose up -d

2. Iniciar API Backend y Orquestador

cd ../2_backend_orquestador
pip install -r requirements.txt
python api.py

3. Iniciar Dashboard Frontend

cd ../3_frontend_dashboard
npm install
npm run dev

---

## Acceso web

http://localhost:5173

---

## Criterios del Quality Gate

Nivel de Severidad  | Criterio              | Comportamiento CI/CD
CRITICAL / HIGH     | Mayor a 0 fallos      | BLOQUEADO: Cancela la integración y bloquea el merge en GitHub
MEDIUM / LOW        | Registro informativo  | APROBADO: Permite el despliegue con advertencias

---

## Guarda los cambios con **`Ctrl + S`**.

---

## Subir la actualización a GitHub

---