"""Phase 8 configuration: World Monitor env keys are optional and never default
to a fabricated URL. Empty configuration means status=not_configured."""

import pytest

from app.config import Settings, settings


def test_world_monitor_settings_default_to_not_configured():
    assert getattr(settings, "world_monitor_base_url", "MISSING") is None
    assert getattr(settings, "world_monitor_api_base_url", "MISSING") is None
    assert getattr(settings, "world_monitor_openapi_url", "MISSING") is None


def test_world_monitor_settings_are_env_driven(monkeypatch):
    monkeypatch.setenv("WORLD_MONITOR_BASE_URL", "https://wm.example.internal")
    monkeypatch.setenv("WORLD_MONITOR_API_BASE_URL", "https://wm.example.internal/api/v1")
    monkeypatch.setenv("WORLD_MONITOR_OPENAPI_URL", "https://wm.example.internal/openapi.json")
    fresh = Settings()
    assert fresh.world_monitor_base_url == "https://wm.example.internal"
    assert fresh.world_monitor_api_base_url == "https://wm.example.internal/api/v1"
    assert fresh.world_monitor_openapi_url == "https://wm.example.internal/openapi.json"


def test_world_monitor_urls_are_never_guessed(monkeypatch):
    monkeypatch.delenv("WORLD_MONITOR_BASE_URL", raising=False)
    monkeypatch.delenv("WORLD_MONITOR_API_BASE_URL", raising=False)
    monkeypatch.delenv("WORLD_MONITOR_OPENAPI_URL", raising=False)
    fresh = Settings()
    assert fresh.world_monitor_base_url is None
    assert fresh.world_monitor_api_base_url is None
    assert fresh.world_monitor_openapi_url is None