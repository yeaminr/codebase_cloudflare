import os
import pytest
from runner.src import cloudflare_token_service
from runner.src import api_constant
from runner.src import exceptions
from runner.src.model import InputModel
from runner.src import helpers
from runner.src import hashicorp_vault_service


# Tests
def test_set_cloudflare_scoped_token(monkeypatch) -> None:
    monkeypatch.setattr(helpers, "check_initial_token", check_initial_token_mock)
    monkeypatch.setattr(api_constant, "cf_token_ttl_minutes", 1)
    monkeypatch.setattr(helpers, "create_api_token", create_api_token_mock)
    monkeypatch.setattr(helpers, "get_zone_id", get_zone_id_mock)
    monkeypatch.setattr(helpers, "get_permission_groups", get_permission_groups_mock)
    # Success - Zone scoped token
    assert cloudflare_token_service.set_cloudflare_scoped_token(
        InputModel(
            environment="dev",
            action="apply",
            config_type="cdn",
            fqdn="example.com.au",
        )
    ) == (['1234', '1234'], 'api_token')
    # Success - Account scoped token
    assert cloudflare_token_service.set_cloudflare_scoped_token(
        InputModel(
            environment="dev",
            action="plan",
            config_type="account",
            fqdn="example.com.au",
        )
    ) == (['1234'], 'api_token')
    # Error scenario - Initial token missing
    monkeypatch.setattr(helpers, "check_initial_token", check_initial_token_none_mock)
    with pytest.raises(exceptions.TokenServiceMissingInitialApiTokenException):
        cloudflare_token_service.set_cloudflare_scoped_token(
            InputModel(
                environment="dev",
                action="plan",
                config_type="account",
                fqdn="example.com.au",
            )
        )


def test_rotate_cloudflare_initial_token(monkeypatch) -> None:
    #monkeypatch.setattr(helpers, "check_initial_token", check_initial_token_mock)
    monkeypatch.setattr(api_constant, "cf_initial_api_token", "cf_initial_api_token")
    monkeypatch.setattr(api_constant, "cf_initial_api_token_id", "cf_initial_api_token_id")
    monkeypatch.setattr(helpers, "create_api_token", create_api_token_mock)
    monkeypatch.setattr(hashicorp_vault_service, "get_vault_token", get_vault_token_mock)
    monkeypatch.setattr(hashicorp_vault_service, "update_secret_in_vault", update_secret_in_vault_mock)
    monkeypatch.setattr(helpers, "delete_api_token", delete_api_token_mock)

    # Success scenario
    rotoate_token_response = cloudflare_token_service.rotate_cloudflare_initial_token(
        environment="dev"
        )
    assert rotoate_token_response == True


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

def check_initial_token_mock(environment) -> str:
    return "api_token"

def check_initial_token_none_mock(environment):
        return None

def get_vault_token_mock() -> str:
    return "mock_vault_token"

def update_secret_in_vault_mock(url, vault_token, secret_to_update, secret_value) -> str:
    return "mock_response"

def delete_api_token_mock(api_token, token_id) -> None:
    pass
