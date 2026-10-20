from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
from pathlib import Path
from pathlib import PureWindowsPath
from typing import Any

import urllib3
from fastapi import Body, Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware

def legacy_identity(authorization: str = Header(default="")) -> dict[str, str]:
    try:
        scheme, separator, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not token or " " in token:
            raise ValueError("invalid token")
        payload, signature = token.split(".")
        secret = os.getenv("AUTH_TOKEN_SECRET", "")
        key = secret.encode("utf-8")
        if len(key) < 32:
            raise ValueError("invalid token")
        signature_bytes = base64.b64decode(signature + "=" * (-len(signature) % 4), altchars=b"-_", validate=True)
        expected_signature = hmac.new(key, payload.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(signature_bytes, expected_signature):
            raise ValueError("invalid token")
        claims_bytes = base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
        claims = json.loads(claims_bytes)
        if (
            not isinstance(claims, dict)
            or not isinstance(claims.get("sub"), str)
            or not claims["sub"]
            or not isinstance(claims.get("role"), str)
            or not claims["role"]
            or type(claims.get("exp")) is not int
            or claims["exp"] <= int(time.time())
        ):
            raise ValueError("invalid token")
        return {"username": claims["sub"], "role": claims["role"]}
    except Exception as error:
        raise HTTPException(status_code=401, detail="Invalid token") from None


def create_app(db_path: str | None = None, upload_dir: str | None = None) -> FastAPI:
    selected_db = db_path or os.getenv("WORKSHOP_DB_PATH", "./data/workshop.db")
    selected_uploads = upload_dir or os.getenv("WORKSHOP_UPLOAD_DIR", "./uploads")
    upload_root = Path(selected_uploads).resolve()
    Path(selected_db).parent.mkdir(parents=True, exist_ok=True)
    upload_root.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(selected_db, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL, owner TEXT NOT NULL, priority TEXT NOT NULL, created_at TEXT NOT NULL)")
    count = connection.execute("SELECT COUNT(*) AS total FROM tasks").fetchone()["total"]
    if count == 0:
        connection.execute("INSERT INTO tasks(title,description,status,owner,priority,created_at) VALUES ('Refactor login','Separar responsabilidades en frontend','TODO','student','HIGH',datetime('now'))")
        connection.execute("INSERT INTO tasks(title,description,status,owner,priority,created_at) VALUES ('Review API','Revisar seguridad de endpoints','IN_PROGRESS','student','MEDIUM',datetime('now'))")
        connection.execute("INSERT INTO tasks(title,description,status,owner,priority,created_at) VALUES ('Trainer notes','Preparar retrospectiva','TODO','trainer','LOW',datetime('now'))")
        connection.commit()

    app = FastAPI(title="Workshop Requirements API", version="0.1.0")
    app.state.connection = connection
    app.state.upload_dir = str(upload_root)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def as_task(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "title": row["title"],
            "description": row["description"],
            "status": row["status"],
            "owner": row["owner"],
            "priority": row["priority"],
            "createdAt": row["created_at"],
        }

    @app.get("/api/tasks")
    def list_tasks(owner: str | None = Query(default=None), identity: dict[str, str] = Depends(legacy_identity)) -> list[dict[str, Any]]:
        requested_owner = owner if owner == identity["username"] else identity["username"]
        rows = connection.execute(
            "SELECT id,title,description,status,owner,priority,created_at FROM tasks WHERE owner=? ORDER BY id",
            (requested_owner,),
        ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            result.append(as_task(row))
        return result

    @app.post("/api/tasks", status_code=201)
    def create_task(payload: dict[str, Any] = Body(...), identity: dict[str, str] = Depends(legacy_identity)) -> dict[str, Any]:
        title = str(payload.get("title", ""))
        description = str(payload.get("description", ""))
        status = str(payload.get("status", "TODO"))
        priority = str(payload.get("priority", "MEDIUM"))
        owner = identity["username"]
        cursor = connection.execute(
            "INSERT INTO tasks(title,description,status,owner,priority,created_at) VALUES (?,?,?,?,?,datetime('now'))",
            (title, description, status, owner, priority),
        )
        connection.commit()
        row = connection.execute("SELECT id,title,description,status,owner,priority,created_at FROM tasks WHERE id=" + str(cursor.lastrowid)).fetchone()
        return as_task(row)

    @app.get("/api/summary")
    def summary(owner: str | None = Query(default=None), identity: dict[str, str] = Depends(legacy_identity)) -> dict[str, Any]:
        requested_owner = owner if owner == identity["username"] else identity["username"]
        rows = connection.execute(
            "SELECT status,priority FROM tasks WHERE owner=?",
            (requested_owner,),
        ).fetchall()
        response: dict[str, Any] = {"owner": requested_owner, "total": 0, "byStatus": {}, "highPriorityOpen": 0}
        for row in rows:
            response["total"] = response["total"] + 1
            if row["status"] in response["byStatus"]:
                response["byStatus"][row["status"]] = response["byStatus"][row["status"]] + 1
            else:
                response["byStatus"][row["status"]] = 1
            if row["priority"] == "HIGH":
                if row["status"] != "DONE":
                    if row["status"] != "ARCHIVED":
                        response["highPriorityOpen"] = response["highPriorityOpen"] + 1
        return response

    @app.post("/api/requirements", status_code=201)
    async def upload_requirement(file: UploadFile = File(...), identity: dict[str, str] = Depends(legacy_identity)) -> dict[str, Any]:
        filename = str(file.filename or "")
        if (
            not filename
            or filename in {".", ".."}
            or "/" in filename
            or "\\" in filename
            or ":" in filename
            or PureWindowsPath(filename).drive
        ):
            raise HTTPException(status_code=400, detail="Invalid file name")
        target = (upload_root / filename).resolve()
        if not target.is_relative_to(upload_root):
            raise HTTPException(status_code=400, detail="Invalid file name")
        content = await file.read()
        target.write_bytes(content)
        return {"owner": identity["username"], "fileName": filename, "storedAt": str(target), "size": len(content)}

    @app.get("/api/backend-health")
    def backend_health(identity: dict[str, str] = Depends(legacy_identity)) -> dict[str, Any]:
        url = os.getenv("AUTH_HEALTH_URL", "http://localhost:8080/q/health")
        try:
            response = urllib3.PoolManager().request("GET", url, timeout=3.0)
            return {"requestedBy": identity["username"], "status": response.status, "body": response.data.decode("utf-8")}
        except Exception as error:
            return {"requestedBy": identity["username"], "status": 0, "body": str(error)}

    @app.on_event("shutdown")
    def close_connection() -> None:
        connection.close()

    return app


app = create_app()
