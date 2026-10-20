# Workshop Requirements API — Python FastAPI

> **Laboratorio intencionalmente vulnerable.** Ejecutar únicamente en local, repositorios privados y ambientes aislados. No publicar en Internet ni desplegar en CERT/PROD.

API FastAPI que administra tareas del workshop y recibe archivos de requerimientos. Usa SQLite y consume el token emitido por el backend Quarkus.

## Ejecución

Requisitos: Python 3.13.

Configura `AUTH_TOKEN_SECRET` con el mismo valor usado por `workshop-auth-backend` y con al menos 32 bytes UTF-8. No hay una clave predeterminada; usa un valor aleatorio y no lo guardes en el repositorio. Los tokens emitidos antes del cambio ya no son válidos: inicia sesión otra vez.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Swagger: `http://localhost:8000/docs`

## Endpoints

- `GET /api/tasks`
- `POST /api/tasks`
- `GET /api/summary`
- `POST /api/requirements`
- `GET /api/backend-health`

La API verifica tokens HMAC, liga el acceso a la identidad autenticada, parametriza SQL y mantiene las cargas dentro del directorio configurado. Permanecen otras deudas del laboratorio, como conexión global, lógica monolítica y dependencias con CVEs.
