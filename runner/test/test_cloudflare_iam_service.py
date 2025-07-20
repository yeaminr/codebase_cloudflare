import os
import pytest
from runner.src import cloudflare_iam_service
from runner.src import cloudflare_token_service
from runner.src import api_constant
from runner.src import exceptions
from runner.src import helpers
from cloudflare import Cloudflare

# Unit tests
def test_add_zone_to_domain_group(monkeypatch) -> None:
    monkeypatch.setattr(helpers, "check_initial_token", check_initial_token_mock)
    monkeypatch.setattr(cloudflare_token_service, "create_read_zone_token", create_read_zone_token_mock)
    monkeypatch.setattr(helpers, "get_zone_id", get_zone_id_mock)
    monkeypatch.setattr(helpers, "get_permission_groups", get_permission_groups_mock)
    monkeypatch.setattr(cloudflare_token_service, "create_account_level_scoped_token", create_account_level_scoped_token_mock)
    monkeypatch.setattr(cloudflare_iam_service, "update_domain_group", update_domain_group_mock)
    monkeypatch.setattr(cloudflare_token_service, "delete_all_tokens", delete_all_tokens_mock)

    # Success scenario
    domain_group_response = cloudflare_iam_service.add_zone_to_domain_group (
        environment="dev",
        fqdn="example.com.au",
        )
    assert domain_group_response != []

    # Error scenario - wrong parameter
    monkeypatch.setattr(cloudflare_iam_service, "update_domain_group", None)
    with pytest.raises(exceptions.CloudflareIAMServiceException):
        domain_group_response = cloudflare_iam_service.add_zone_to_domain_group (
            environment="tst",
            fqdn="example.com.au",
            )

    # Error scenario - Initial token missing
    monkeypatch.setattr(helpers, "check_initial_token", check_initial_token_none_mock)
    with pytest.raises(exceptions.TokenServiceMissingInitialApiTokenException):
        cloudflare_iam_service.add_zone_to_domain_group(
            environment="dev",
            fqdn="example.com.au",
        )

def test_update_domain_group(monkeypatch) -> None:
    monkeypatch.setattr(cloudflare_iam_service, "get_domain_group", get_domain_group_mock)
    monkeypatch.setattr(Cloudflare, "__init__", MockCloudflare.__init__)

    # Success scenario
    domain_group_response = cloudflare_iam_service.update_domain_group (
        account_id="a14e1714108d2ee225fcbd3eaa28a1f1",
        resource_group_id="d42a938a30a44b148d31514b1c5be87a",
        zone_id="883727ede6bfab28b780dbbe1372a205",
        scoped_api_token="1234567890"
        )
    assert domain_group_response != []


# Mocks

def get_zone_id_mock(zone_name, zone_read_token) -> str:
    return "zoneid"
def create_read_zone_token_mock(cf_initial_api_token, account_id, token_store) -> tuple[str, list]:
    return "api_token" , ["api_token_id"]
def get_permission_groups_mock(cf_initial_api_token, token_permissions) -> str:
    return "api_token"
def create_account_level_scoped_token_mock(cf_initial_api_token, token_permissions, account_id, token_store, token_name) -> tuple[str, list]:
    return "api_token", ["api_token_id"]
def update_domain_group_mock(account_id, resource_group_id, zone_id, scoped_api_token) -> list:
    return "resource_groups_scope_objects"
def delete_all_tokens_mock(initial_token, token_store) -> list:
    return []
def get_domain_group_mock(account_id, resource_group_id, scoped_api_token) -> list:
    return [{'key': 'com.cloudflare.api.account.zone.0d022ca2f50ab6ccea92775b4b8e62cc'}]
def check_initial_token_mock(environment) -> str:
    return "api_token"
def check_initial_token_none_mock(environment):
        return None

class MockCloudflare:
    def __init__(self, api_token):
        self.iam = Iam

class ResourceGroups:
    def update(account_id, resource_group_id, scope) -> list:
        return [{'key': 'ok'}]

    def get(account_id, resource_group_id) -> list:
        return [{'key': 'ok'}]

class Iam:
    resource_groups = ResourceGroups
