import pytest
from pydantic import ValidationError
from runner.src.api_config import APIConfig


def test_api_config(monkeypatch):
    monkeypatch.delenv("SNOW_HOST_URL", raising=False)
    with pytest.raises(ValidationError):
        APIConfig()
