from datetime import datetime, timedelta
import requests
import pytest
import jwt
from jwt.algorithms import RSAAlgorithm
from fastapi import HTTPException
import yaml
from runner.src import api_constant, auth_service, github_service
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src import exceptions
from runner.src.exceptions import AuthJKWSFetchException
from runner.src.model import InputModel

# Common Input
# Common Input
input_model = InputModel(
    environment="dev", action="plan", config_type="zone", fqdn="zone_name"
)
jwt_token_info = JWTTokenInfo(
    repo_name="repo_name",
    branch_name="abc",
    authorized=True,
    org_name="CBA-General",
)

# Test
def test_fetch_github_jkws_success(monkeypatch):
    # From Cache - Expiry after 10 seconds
    monkeypatch.setitem(auth_service.jkws_cache, "data", JWKS)
    monkeypatch.setitem(
        auth_service.jkws_cache, "expires_at", datetime.now() + timedelta(seconds=10)
    )
    assert auth_service.fetch_github_jkws() == JWKS

    # Cache expired - Retry
    monkeypatch.setitem(
        auth_service.jkws_cache, "expires_at", datetime.now() - timedelta(seconds=10)
    )
    monkeypatch.setattr(requests, "get", mock_jwks_requests_get_success)
    assert auth_service.fetch_github_jkws() == JWKS

    # Cahce None - From Github
    monkeypatch.setitem(auth_service.jkws_cache, "data", None)
    monkeypatch.setattr(requests, "get", mock_jwks_requests_get_success)
    assert auth_service.fetch_github_jkws() == JWKS

    # Github request exception
    monkeypatch.setitem(auth_service.jkws_cache, "data", None)
    monkeypatch.setattr(requests, "get", mock_jwks_requests_get_exception)
    with pytest.raises(AuthJKWSFetchException):
        auth_service.fetch_github_jkws()


def test_verify_token(monkeypatch):
    # X-Github-Auth-Header not found
    mock_request = MockRequest({})
    with pytest.raises(HTTPException):
        auth_service.verify_token(mock_request)

    # X-Github-Auth-Header does not have Bearer token
    mock_request = MockRequest({"X-Github-Auth-Header": "token"})
    with pytest.raises(HTTPException):
        auth_service.verify_token(mock_request)

    # Success case - from cache
    mock_request = MockRequest({"X-Github-Auth-Header": "Bearer token"})
    monkeypatch.setattr(jwt, "get_unverified_header", mock_jwt_get_unverified_header)
    monkeypatch.setattr(RSAAlgorithm, "from_jwk", mock_rsa_algorithm_from_jwk)
    monkeypatch.setattr(jwt, "decode", mock_jwt_decode)
    monkeypatch.setitem(auth_service.jkws_cache, "data", JWKS)
    monkeypatch.setitem(
        auth_service.jkws_cache, "expires_at", datetime.now() + timedelta(seconds=10)
    )
    jwt_token = auth_service.verify_token(mock_request)
    assert (
        jwt_token.authorized
        and jwt_token.repo_name == "codebase"
        and jwt_token.org_name == "CBA-General"
        and jwt_token.branch_name == "main"
    )

    # JWK Public key not found so retry once
    monkeypatch.setitem(auth_service.jkws_cache, "data", NOT_FOUND_JWKS)
    monkeypatch.setattr(requests, "get", mock_jwks_requests_get_success)
    jwt_token = auth_service.verify_token(mock_request)
    assert (
        jwt_token.authorized
        and jwt_token.repo_name == "codebase"
        and jwt_token.org_name == "CBA-General"
        and jwt_token.branch_name == "main"
    )

    # JWK Public key not found so retry twice
    monkeypatch.setitem(auth_service.jkws_cache, "data", NOT_FOUND_JWKS)
    monkeypatch.setattr(requests, "get", mock_jwks_requests_not_found)
    with pytest.raises(HTTPException):
        auth_service.verify_token(mock_request)


def test_verify_repo_action(monkeypatch):
    # Action apply - Branch not main - Result should be false
    input_model.action = "apply"
    jwt_token_info.branch_name = "not_main"
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is False

    # Action apply - Branch main - Config type zone - Allowed fqdn - Result should be true
    input_model.action = "apply"
    jwt_token_info.branch_name = "main"
    input_model.config_type = "zone"
    monkeypatch.setattr(auth_service, "fetch_selfservice_repo_tenants", lambda x: "tenant_file_content")
    monkeypatch.setattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", lambda x, y, z: True)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is True

    # Action apply - Branch main - Config type zone - Not allowed fqdn - Result should be false
    input_model.action = "apply"
    jwt_token_info.branch_name = "main"
    input_model.config_type = "zone"
    monkeypatch.setattr(auth_service, "fetch_selfservice_repo_tenants", lambda x: "tenant_file_content")
    monkeypatch.setattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", lambda x, y, z: False)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is False

    # Action plan - Branch main - Config type zone - Allowed fqdn - Result should be true
    input_model.action = "plan"
    jwt_token_info.branch_name = "main"
    input_model.config_type = "zone"
    monkeypatch.setattr(auth_service, "fetch_selfservice_repo_tenants", lambda x: "tenant_file_content")
    monkeypatch.setattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", lambda x, y, z: True)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is True

    # Action plan - Branch main - Config type zone - Allowed fqdn - Result should be true
    input_model.action = "plan"
    jwt_token_info.branch_name = "main"
    input_model.config_type = "zone"
    monkeypatch.setattr(auth_service, "fetch_selfservice_repo_tenants", lambda x: "tenant_file_content")
    monkeypatch.setattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", lambda x, y, z: True)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is True

    # Action plan - Branch not main - Config type zone - Allowed fqdn - Result should be true
    input_model.action = "plan"
    jwt_token_info.branch_name = "not_main"
    input_model.config_type = "zone"
    monkeypatch.setattr(auth_service, "fetch_selfservice_repo_tenants", lambda x: "tenant_file_content")
    monkeypatch.setattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", lambda x, y, z: True)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is True

    # Action plan - Branch not main - Config type zone - Allowed fqdn - Result should be true
    input_model.action = "plan"
    jwt_token_info.branch_name = "not_main"
    input_model.config_type = "zone"
    monkeypatch.setattr(auth_service, "fetch_selfservice_repo_tenants", lambda x: "tenant_file_content")
    monkeypatch.setattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", lambda x, y, z: True)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is True

    # Action plan - Branch not main - Config type zone - Zone content not found - Result should be false
    input_model.action = "plan"
    jwt_token_info.branch_name = "not_main"
    input_model.config_type = "zone"
    monkeypatch.setattr(auth_service, "fetch_selfservice_repo_tenants", lambda x: None)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is False

    # fetch_selfservice_repo_tenants exception
    monkeypatch.setattr(auth_service, "fetch_selfservice_repo_tenants", raise_generic_exception)
    with pytest.raises(HTTPException):
        auth_service.verify_repo_action(jwt_token_info, input_model)

    # is_requesting_repo_authorized_to_action_on_cf_zone exception
    monkeypatch.setattr(auth_service, "fetch_selfservice_repo_tenants", lambda x: "tenant_file_content")
    monkeypatch.setattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", raise_generic_exception)
    with pytest.raises(HTTPException):
        auth_service.verify_repo_action(jwt_token_info, input_model)

    # Action apply - Branch main - Config type account - Authorized account repo - Result should be true
    input_model.action = "apply"
    jwt_token_info.branch_name = "main"
    input_model.config_type = "account"
    jwt_token_info.repo_name = api_constant.AUTHORIZED_ACCOUNT_REPOS[0]
    monkeypatch.delattr(auth_service, "fetch_selfservice_repo_tenants", raising=False)
    monkeypatch.delattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", raising=False)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is True


    # Action apply - Branch main - Config type account - Authorized account repo - Result should be true
    input_model.action = "apply"
    jwt_token_info.branch_name = "main"
    input_model.config_type = "account"
    jwt_token_info.repo_name = "unauthorized_account_repo"
    monkeypatch.delattr(auth_service, "fetch_selfservice_repo_tenants", raising=False)
    monkeypatch.delattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", raising=False)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is False

    # Action plan - Branch main - Config type account - Authorized account repo - Result should be true
    input_model.action = "plan"
    jwt_token_info.branch_name = "main"
    input_model.config_type = "account"
    jwt_token_info.repo_name = api_constant.AUTHORIZED_ACCOUNT_REPOS[0]
    monkeypatch.delattr(auth_service, "fetch_selfservice_repo_tenants", raising=False)
    monkeypatch.delattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", raising=False)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is True


    # Action plan - Branch main - Config type account - Authorized account repo - Result should be true
    input_model.action = "plan"
    jwt_token_info.branch_name = "main"
    input_model.config_type = "account"
    jwt_token_info.repo_name = "unauthorized_account_repo"
    monkeypatch.delattr(auth_service, "fetch_selfservice_repo_tenants", raising=False)
    monkeypatch.delattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", raising=False)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is False

    # Action plan - Branch not main - Config type account - Authorized account repo - Result should be true
    input_model.action = "plan"
    jwt_token_info.branch_name = "not_main"
    input_model.config_type = "account"
    jwt_token_info.repo_name = api_constant.AUTHORIZED_ACCOUNT_REPOS[0]
    monkeypatch.delattr(auth_service, "fetch_selfservice_repo_tenants", raising=False)
    monkeypatch.delattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", raising=False)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is True


    # Action plan - Branch not main - Config type account - Authorized account repo - Result should be true
    input_model.action = "plan"
    jwt_token_info.branch_name = "not_main"
    input_model.config_type = "account"
    jwt_token_info.repo_name = "unauthorized_account_repo"
    monkeypatch.delattr(auth_service, "fetch_selfservice_repo_tenants", raising=False)
    monkeypatch.delattr(auth_service, "is_requesting_repo_authorized_to_action_on_cf_zone", raising=False)
    assert auth_service.verify_repo_action(jwt_token_info, input_model) is False


def test_is_requesting_repo_authorized_to_action_on_cf_zone(monkeypatch):
    yaml_file = "tenant_onboarding_settings.yml"
    monkeypatch.setattr(api_constant, "TENANT_ONBOARDING_YAML", yaml_file)

    data = {
        "dev_fqdns": ["dev_hostname"],
        "tst_fqdns": ["tst_hostname"],
        "stg_fqdns": ["stg_hostname"],
        "prd_fqdns": ["prd_hostname"],
    }

    # success
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("dev", "dev_hostname", data) is True 
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("tst", "tst_hostname", data) is True
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("stg", "stg_hostname", data) is True
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("prd", "prd_hostname", data) is True

    # not in allowed fqdn
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("dev", "not_found", data) is False 
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("tst", "not_found", data) is False
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("stg", "not_found", data) is False
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("prd", "not_found", data) is False

    # key not present
    data = {
        "dev_fqdns": ["dev_hostname"],
    }
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("tst", "tst_hostname", data) is False
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("stg", "stg_hostname", data) is False
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("prd", "prd_hostname", data) is False

    data = {
        "tst_fqdns": ["tst_hostname"],
    }
    assert auth_service.is_requesting_repo_authorized_to_action_on_cf_zone("dev", "dev_hostname", data) is False


def test_fetch_selfservice_repo_tenants(monkeypatch):
    data = {"dev_fqdns": ["dev_hostname"]}
    data_stream = yaml.dump(data)

    # success
    repo_name = "CBA-Edge-Security-Platform-RSTD/groupsec-edgesecurity-tenant-repo_name"
    monkeypatch.setattr(github_service, "get_download_url", lambda x, y, z: "download_url")
    monkeypatch.setattr(github_service, "get_file_content", lambda x: data_stream)
    assert auth_service.fetch_selfservice_repo_tenants(repo_name) == data

    # invalid tenant repo name
    assert auth_service.fetch_selfservice_repo_tenants("tenant_repo_name") is None

    # get_file_content cant find file
    monkeypatch.setattr(github_service, "get_download_url", lambda x, y, z: "download_url")
    monkeypatch.setattr(github_service, "get_file_content", raise_github_service_file_fetch_exception)
    assert auth_service.fetch_selfservice_repo_tenants(repo_name) is None

# Mock
JWKS = {
    "keys": [
        {
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": "key_id",
            "n": "n_value",
            "e": "AQAB",
        }
    ]
}

NOT_FOUND_JWKS = {"keys": [{"kid": "not_found_key_id"}]}


class MockRequest:
    def __init__(self, headers):
        self.headers = headers


class MockResponse:
    def __init__(self, json_data, status_code):
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data


def mock_fetch_github_jkws():
    return JWKS


def mock_jwks_requests_get_success(*args, **kwargs):
    return MockResponse(
        JWKS,
        200,
    )

def mock_jwks_requests_not_found(*args, **kwargs):
    return MockResponse(
        NOT_FOUND_JWKS,
        200,
    )


def mock_jwks_requests_get_success_not_found(*args, **kwargs):
    return MockResponse(
        {"keys": []},
        200,
    )


def mock_jwks_requests_get_exception(*args, **kwargs):
    return MockResponse({"error": "500"}, 500)

def mock_jwt_get_unverified_header(jwt_token):
    return {"alg": "RS256", "kid": "key_id"}


def mock_rsa_algorithm_from_jwk(jwk):
    return "public_key"


def mock_jwt_decode(jwt_token, public_key, algorithms, issuer, audience, leeway):
    return {
        "repository": "codebase",
        "repository_owner": "CBA-General",
        "ref": "refs/heads/main",
    }

def raise_generic_exception(self, *args, **kwargs):
    raise Exception("Error")
    

def raise_github_service_file_fetch_exception(*args, **kwargs):
    raise exceptions.GithubServiceFileFetchException