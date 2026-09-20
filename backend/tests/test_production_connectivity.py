import os
import pytest
from starlette.testclient import TestClient

from app.core.config import Settings
from app.main import app
from app.scanner.orchestrator import OrionScanner


def test_cors_settings_from_env_json(monkeypatch):
    monkeypatch.setenv("ORION_CORS_ORIGINS", '["https://orion-one-alpha.vercel.app","http://localhost:5173"]')
    s = Settings()
    assert s.cors_origins == [
        "https://orion-one-alpha.vercel.app",
        "http://localhost:5173",
    ]


def test_cors_settings_from_env_comma(monkeypatch):
    monkeypatch.setenv("ORION_CORS_ORIGINS", "https://orion-one-alpha.vercel.app,http://localhost:5173")
    s = Settings()
    assert s.cors_origins == [
        "https://orion-one-alpha.vercel.app",
        "http://localhost:5173",
    ]


def test_cors_settings_from_env_quoted_comma(monkeypatch):
    monkeypatch.setenv("ORION_CORS_ORIGINS", ' "https://orion-one-alpha.vercel.app" , "http://localhost:5173" ')
    s = Settings()
    assert s.cors_origins == [
        "https://orion-one-alpha.vercel.app",
        "http://localhost:5173",
    ]


def test_cors_settings_default(monkeypatch):
    monkeypatch.delenv("ORION_CORS_ORIGINS", raising=False)
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    s = Settings(_env_file=None)
    assert s.cors_origins == [
        "http://localhost:5173",
        "https://orion-one-alpha.vercel.app",
    ]


def test_cors_preflight_options():
    client = TestClient(app)

    # Preflight from Vercel frontend
    response = client.options(
        "/api/v1/auth/register",
        headers={
            "Origin": "https://orion-one-alpha.vercel.app",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,Authorization",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "https://orion-one-alpha.vercel.app"
    assert response.headers.get("access-control-allow-credentials") == "true"

    # Preflight from localhost
    response_local = client.options(
        "/api/v1/auth/register",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,Authorization",
        },
    )
    assert response_local.status_code == 200
    assert response_local.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_scanner_components_loaded_in_backend():
    scanner = OrionScanner()
    assert len(scanner.scanner_types) >= 15
    assert "security_headers" in scanner.scanner_types
    assert "sqli" in scanner.scanner_types
    assert "xss" in scanner.scanner_types
    assert "csrf" in scanner.scanner_types
    assert "cors" in scanner.scanner_types
    assert "ssrf" in scanner.scanner_types


def test_health_endpoints():
    client = TestClient(app)
    res1 = client.get("/health")
    assert res1.status_code == 200
    assert res1.json()["status"] == "ok"

    res2 = client.get("/api/v1/health")
    assert res2.status_code == 200
    assert res2.json()["status"] == "ok"
