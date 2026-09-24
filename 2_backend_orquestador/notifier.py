import os
import requests

def enviar_alerta_calidad(estado_gate, commit_hash, total_criticas, total_altas, total_medias, total_bajas):
    """
    Envía una tarjeta interactiva (embed) a Discord con los resultados del Quality Gate.
    """
    webhook_url = os.getenv("DEVSECOPS_WEBHOOK_URL")

    if not webhook_url:
        print("[!] Variable DEVSECOPS_WEBHOOK_URL no definida. Omitiendo notificación.")
        return

    es_bloqueado = estado_gate == "Bloqueado"
    # Rojo (#E74C3C) si fue bloqueado, Verde (#2ECC71) si fue aprobado
    color = 15158332 if es_bloqueado else 3066993
    icono = "🚨" if es_bloqueado else "✅"

    payload = {
        "username": "DevSecOps Quality Gate",
        "avatar_url": "https://cdn-icons-png.flaticon.com/512/9442/9442999.png",
        "embeds": [
            {
                "title": f"{icono} Decisión del Quality Gate: {estado_gate.upper()}",
                "description": f"Auditoría automatizada finalizada para el commit `{commit_hash[:8] if commit_hash else 'Local'}`",
                "color": color,
                "fields": [
                    {"name": "Críticas", "value": str(total_criticas), "inline": True},
                    {"name": "Altas", "value": str(total_altas), "inline": True},
                    {"name": "Medias / Bajas", "value": f"{total_medias} / {total_bajas}", "inline": True},
                ],
                "footer": {
                    "text": "Plataforma DevSecOps • CI/CD Pipeline"
                }
            }
        ]
    }

    try:
        response = requests.post(webhook_url, json=payload, timeout=8)
        if response.status_code in [200, 204]:
            print("[+] Notificación enviada exitosamente al canal de Discord.")
        else:
            print(f"[!] Discord respondió con código de estado: {response.status_code}")
    except Exception as e:
        print(f"[!] Error de conexión enviando notificación a Discord: {e}")