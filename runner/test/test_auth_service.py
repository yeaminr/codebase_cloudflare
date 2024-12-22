from datetime import datetime, timedelta
import requests
import pytest
import jwt
from jwt.algorithms import RSAAlgorithm
from fastapi import HTTPException
from runner.src import auth_service
from runner.src.exceptions import AuthJKWSFetchException


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
