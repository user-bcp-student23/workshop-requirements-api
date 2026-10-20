import base64
import hashlib
import hmac
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

TEST_SECRET = "workshop-test-only-token-secret-32-bytes-minimum"


@pytest.fixture(autouse=True)
def configure_token_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_TOKEN_SECRET", TEST_SECRET)


def token(username: str = "student", role: str = "STUDENT", expires_at: int | None = None) -> str:
    claims = {"sub": username, "role": role, "exp": expires_at or int(time.time()) + 3600}
    payload = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":")).encode()).rstrip(b"=").decode()
    signature = hmac.new(TEST_SECRET.encode(), payload.encode("ascii"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{payload}.{encoded_signature}"


def headers(username: str = "student", role: str = "STUDENT") -> dict[str, str]:
    return {"Authorization": f"Bearer {token(username, role)}"}


def test_lists_seeded_tasks(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers=headers())
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_creates_task_and_summary(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        created = client.post(
            "/api/tasks",
            headers=headers(),
            json={"title": "Add tests", "description": "Improve coverage", "status": "TODO", "priority": "HIGH"},
        )
        summary = client.get("/api/summary", headers=headers())
    assert created.status_code == 201
    assert created.json()["owner"] == "student"
    assert summary.json()["total"] == 3


def test_sql_inputs_are_treated_as_data(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        created = client.post(
            "/api/tasks",
            headers=headers(username="O'Brien"),
            json={
                "title": "Review O'Brien's API",
                "description": "It's a literal value",
                "owner": "O'Brien",
            },
        )
        listed = client.get("/api/tasks", headers=headers(username="O'Brien"), params={"owner": "O'Brien"})
        summary = client.get("/api/summary", headers=headers(username="O'Brien"), params={"owner": "O'Brien"})
        manipulated = client.get("/api/tasks", headers=headers(username="' OR 1=1 --"))

    assert created.status_code == 201
    assert created.json()["title"] == "Review O'Brien's API"
    assert listed.status_code == 200
    assert [task["title"] for task in listed.json()] == ["Review O'Brien's API"]
    assert summary.json()["owner"] == "O'Brien"
    assert summary.json()["total"] == 1
    assert manipulated.status_code == 200
    assert manipulated.json() == []


def test_uploads_requirement(tmp_path: Path) -> None:
    upload_dir = tmp_path / "uploads"
    app = create_app(str(tmp_path / "workshop.db"), str(upload_dir))
    with TestClient(app) as client:
        response = client.post(
            "/api/requirements",
            headers=headers(),
            files={"file": ("requirements.txt", b"Login must be accessible", "text/plain")},
        )
    assert response.status_code == 201
    assert (upload_dir / "requirements.txt").exists()


def test_rejects_upload_path_components(tmp_path: Path) -> None:
    upload_dir = tmp_path / "uploads"
    app = create_app(str(tmp_path / "workshop.db"), str(upload_dir))
    filenames = ("../outside.txt", "..\\outside.txt", str(tmp_path / "outside.txt"))

    with TestClient(app) as client:
        responses = [
            client.post(
                "/api/requirements",
                headers=headers(),
                files={"file": (filename, b"not written outside", "text/plain")},
            )
            for filename in filenames
        ]

    assert [response.status_code for response in responses] == [400, 400, 201]
    assert Path(responses[2].json()["storedAt"]).parent == upload_dir.resolve()
    assert (upload_dir / "outside.txt").exists()
    assert not (tmp_path / "outside.txt").exists()


def test_rejects_invalid_token(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers={"Authorization": "Bearer invalid"})
    assert response.status_code == 401


def test_rejects_tampered_and_legacy_tokens(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    payload, signature = token().split(".")
    altered_claims = {"sub": "trainer", "role": "TRAINER", "exp": int(time.time()) + 3600}
    altered_payload = base64.urlsafe_b64encode(
        json.dumps(altered_claims, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    old_format = base64.b64encode(f"trainer|TRAINER|{int(time.time()) + 3600}|WORKSHOP_SECRET_2026".encode()).decode()

    with TestClient(app) as client:
        tampered = client.get("/api/tasks", headers={"Authorization": f"Bearer {altered_payload}.{signature}"})
        legacy = client.get("/api/tasks", headers={"Authorization": f"Bearer {old_format}"})

    assert tampered.status_code == 401
    assert legacy.status_code == 401


def test_rejects_expired_token(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    expired = token(expires_at=int(time.time()) - 1)

    with TestClient(app) as client:
        response = client.get("/api/tasks", headers={"Authorization": f"Bearer {expired}"})

    assert response.status_code == 401


def test_owner_cannot_expand_access_or_create_for_another_user(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        listed = client.get("/api/tasks", headers=headers(), params={"owner": "trainer"})
        summary = client.get("/api/summary", headers=headers(), params={"owner": "trainer"})
        created = client.post(
            "/api/tasks",
            headers=headers(),
            json={"title": "Student task", "description": "Owned by the caller", "owner": "trainer"},
        )

    assert listed.status_code == 200
    assert {task["owner"] for task in listed.json()} == {"student"}
    assert summary.json()["owner"] == "student"
    assert summary.json()["total"] == 2
    assert created.status_code == 201
    assert created.json()["owner"] == "student"
