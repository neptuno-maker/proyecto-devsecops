# Plataforma Automatizada DevSecOps & Quality Gate

[![Pipeline DevSecOps & Quality Gate](https://github.com/neptuno-maker/proyecto-devsecops/actions/workflows/devsecops-pipeline.yml/badge.svg)](https://github.com/neptuno-maker/proyecto-devsecops/actions/workflows/devsecops-pipeline.yml)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL%2015-316192?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Python](https://img.shields.io/badge/Orchestrator-Python%203.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![React](https://img.shields.io/badge/Dashboard-React%20%2B%20Vite-61DAFB?logo=react&logoColor=black)](https://reactjs.org/)
[![Pytest](https://img.shields.io/badge/Testing-Pytest-0A9EDC?logo=pytest&logoColor=white)](https://docs.pytest.org/)

Plataforma integral de seguridad continua (DevSecOps) diseñada para auditar, persistir y visualizar el estado de seguridad del código fuente, dependencias y servicios web en un ciclo de Integración Continua (CI/CD).

---

## Arquitectura del Sistema

```text
[ Git Push / PR ]
       │
       ▼
[ GitHub Actions Runner ]
├── 1. Unit Tests (Pytest) ────────> [ Validación de Módulos ]
├── 2. SAST Engine (Bandit) ───────> [ CWE / Inyecciones en Código ]
├── 3. SCA Engine (pip-audit) ────> [ CVE / Vulnerabilidades en Librerías ]
├── 4. DAST Engine (OWASP ZAP) ────> [ Detección Dinámica en Endpoints ]
├── 5. Quality Gate Evaluator ────> [ Bloqueo / Aprobación Autónoma ]
└── 6. PostgreSQL (Persistencia) ──> [ Histórico de Auditorías ]
       │
       ▼
[ Frontend Dashboard (React) ] ─────> [ Métricas, Filtros, Exportación PDF/CSV ]
```

## Capacidades Principales

Pruebas Unitarias Automatizadas: Verificación funcional previa al despliegue mediante pytest para garantizar la estabilidad del motor orquestador y parsers de auditoría.

Análisis SAST (Static Application Security Testing): Detección estática temprana de fallos de seguridad en código Python mediante Bandit.

Análisis SCA (Software Composition Analysis): Identificación automatizada de vulnerabilidades y exposiciones conocidas (CVE) en librerías externas mediante pip-audit.

Análisis DAST (Dynamic Application Security Testing): Simulación de ataques externos en tiempo de ejecución contra la aplicación mediante escaneo dinámico con OWASP ZAP.

Quality Gate Automatizado: Evaluación rigurosa basada en umbrales de severidad. Si se detectan fallos clasificados como Alta o Crítica, el pipeline bloquea el ciclo de integración de forma autónoma.

Persistencia Relacional: Almacenamiento estructurado de ejecuciones, hallazgos y alertas en PostgreSQL contenerizado.

Dashboard Interactivo: Panel de visualización con autenticación de usuarios, métricas reactivas, gráficas de distribución, historial por commit, asistente de remediación y exportación a PDF/CSV.

## Estructura del Repositorio

├── .github/workflows/
│   └── devsecops-pipeline.yml     # Flujo CI/CD automatizado en GitHub Actions
├── 1_infraestructura/
│   ├── docker-compose.yml         # Orquestación de base de datos PostgreSQL
│   └── init_db.sql                # Esquema de persistencia relacional
├── 2_backend_orquestador/
│   ├── app_prueba/                # Microservicio para análisis de seguridad
│   ├── orquestador.py             # Motor lógico de auditoría y Quality Gate
│   ├── api.py                     # API REST protegida para el Dashboard
│   └── requirements.txt           # Dependencias del backend
├── 3_frontend_dashboard/
│   ├── src/                       # Aplicación cliente React (gráficos, filtros, auth)
│   └── package.json               # Dependencias del frontend
├── test/
│   └── test_orquestador.py        # Suite de pruebas unitarias con Pytest
└── README.md                      # Documentación técnica del proyecto
```