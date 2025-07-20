import os
import pytest
from runner.src import cloudflare_token_service
from runner.src import api_constant
from runner.src import exceptions
from runner.src.model import InputModel
from cf.python.src import helpers


# Tests
def test_set_cloudflare_scoped_token(monkeypatch) -> None:
    monkeypatch.setattr(api_constant, "cf_initial_api_token", "cf_initial_api_token")
    monkeypatch.setattr(api_constant, "cf_token_ttl_minutes", 1)
    monkeypatch.setattr(helpers, "create_api_token", create_api_token_mock)
    monkeypatch.setattr(helpers, "get_zone_id", get_zone_id_mock)
    monkeypatch.setattr(helpers, "get_permission_groups", get_permission_groups_mock)
    # Success - Zone scoped token
    cloudflare_token_service.set_cloudflare_scoped_token(
        InputModel(
            environment="dev",
            action="apply",
            config_type="cdn",
            fqdn="example.com.au",
        )
    )
    assert os.environ["CLOUDFLARE_API_TOKEN"] == "api_token"
    # Success - Account scoped token
    cloudflare_token_service.set_cloudflare_scoped_token(
        InputModel(
            environment="dev",
            action="plan",
            config_type="account",
            fqdn="example.com.au",
        )
    )
    assert os.environ["CLOUDFLARE_API_TOKEN"] == "api_token"
    # Error scenario - Initial token missing
    monkeypatch.setattr(api_constant, "cf_initial_api_token", None)
    with pytest.raises(exceptions.TokenServiceMissingInitialApiTokenException):
        cloudflare_token_service.set_cloudflare_scoped_token(
            InputModel(
                environment="dev",
                action="plan",
                config_type="account",
                fqdn="example.com.au",
            )
        )


# Mocks
def create_api_token_mock(initial_token, token_name, policies, ttl) -> str:
    class Response:
        def __init__(self):
            self.value = "api_token"
            self.id = "1234"
    return Response()


def get_permission_groups_mock(cf_initial_api_token, token_permissions) -> str:
    return "api_token"


def get_zone_id_mock(zone_name, zone_read_token) -> str:
    return "zoneid"
