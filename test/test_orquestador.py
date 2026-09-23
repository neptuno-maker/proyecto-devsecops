import pytest
from unittest.mock import patch, MagicMock
import sys
import os

# Asegurar que la ruta del backend esté en el PATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "2_backend_orquestador")))

from orquestador import (
    leer_reporte_dast_real,
    registrar_alerta_en_bd,
    enviar_notificacion_webhook
)

def test_leer_reporte_dast_sin_archivo():
    """Valida el manejo de fallback si el reporte DAST no existe."""
    resultado = leer_reporte_dast_real("ruta_inexistente.json")
    assert resultado == []

def test_leer_reporte_dast_con_hallazgos():
    """Valida que el parser extraiga correctamente alertas de formato ZAP (Mock CP-01)."""
    mock_data = """{
        "site": [{
            "@name": "http://127.0.0.1:5000",
            "alerts": [{
                "alert": "Missing Anti-clickjacking Header",
                "name": "X-Frame-Options",
                "riskcode": "2",
                "instances": [{"uri": "http://127.0.0.1:5000/login"}]
            }]
        }]
    }"""
    with patch("builtins.open", MagicMock(return_value=MagicMock(__enter__=lambda s: MagicMock(read=lambda: mock_data)))):
        with patch("os.path.exists", return_value=True):
            with patch("json.load", return_value={
                "site": [{
                    "@name": "http://127.0.0.1:5000",
                    "alerts": [{
                        "alert": "Missing Anti-clickjacking Header",
                        "name": "X-Frame-Options",
                        "riskcode": "2",
                        "instances": [{"uri": "http://127.0.0.1:5000/login"}]
                    }]
                }]
            }):
                hallazgos = leer_reporte_dast_real("mock_zap.json")
                assert len(hallazgos) == 1
                assert hallazgos[0]["origen"] == "DAST (OWASP ZAP)"
                assert hallazgos[0]["severidad"] == "Media"

def test_registrar_alerta_en_bd():
    """Valida la inserción SQL correcta en la tabla ALERTA_NOTIFICADA."""
    mock_cursor = MagicMock()
    registrar_alerta_en_bd(mock_cursor, 10, "Webhook", "canal-devsecops")
    assert mock_cursor.execute.called
    llamada_sql = mock_cursor.execute.call_args[0][0]
    assert "INSERT INTO ALERTA_NOTIFICADA" in llamada_sql