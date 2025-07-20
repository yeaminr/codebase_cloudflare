import pytest
import jwt
from runner.src import github_service
from runner.src import api_constant
from runner.src import exceptions
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src.model import InputModel


# Tests
def test_main(monkeypatch, requests_mock) -> None:
    monkeypatch.setattr(
        github_service, "generate_installation_jwt", generate_installation_jwt_mock
    )
    monkeypatch.setattr(
        github_service, "download_file_content", download_file_content_mock
    )
    requests_mock.get(
        "https://api.github.com/repos/esm-repo/contents/dev/example.com.au/zone_parameters.yml?ref=feature/pytest",
        json={"content": "dGVzdA=="},
    )
    jwt_token_info = JWTTokenInfo(
        authorized=True,
        repo_name="esm-repo",
        org_name="esm-org",
        branch_name="feature/pytest",
    )
    input_model = InputModel(
        environment="dev", fqdn="example.com.au", config_type="zone"
    )
    github_service.main(
        jwt_token_info=jwt_token_info,
        input_model=input_model,
        working_dir="working_dir",
    )
    requests_mock.get(
        "https://api.github.com/repos/esm-repo/contents/dev/example.com.au/zone_parameters.yml?ref=feature/pytest",
        text="test",
    )
    with pytest.raises(ValueError):
        github_service.main(
            jwt_token_info=jwt_token_info,
            input_model=input_model,
            working_dir="working_dir",
        )
    requests_mock.get(
        "https://api.github.com/repos/esm-repo/contents/dev/example.com.au/zone_parameters.yml?ref=feature/pytest",
        text="Not Found",
        status_code=404,
    )
    with pytest.raises(exceptions.GithubServiceFileFetchException):
        github_service.main(
            jwt_token_info=jwt_token_info,
            input_model=input_model,
            working_dir="working_dir",
        )


def test_generate_installation_jwt(monkeypatch, requests_mock) -> None:
    monkeypatch.setattr(api_constant, "gh_app_installation_id", "1")
    monkeypatch.setattr(api_constant, "gh_signing_key", "gh_signing_key")
    monkeypatch.setattr(api_constant, "gh_app_id", "1")
    monkeypatch.setattr(jwt, "encode", jwt_encode_mock)
    requests_mock.post(
        "https://api.github.com/app/installations/1/access_tokens",
        json={"token": "secret"},
        status_code=201,
    )
    token = github_service.generate_installation_jwt()
    assert token == "secret"
    requests_mock.post(
        "https://api.github.com/app/installations/1/access_tokens",
        json={"token": "error"},
        status_code=500,
    )
    with pytest.raises(ValueError):
        github_service.generate_installation_jwt()


# # Mocks
def jwt_encode_mock(payload, signing_key, algorithm) -> str:
    return "encoded_jwt"


def generate_installation_jwt_mock() -> str:
    return "test-token"


def download_file_content_mock(response_json, file_name, working_dir) -> str:
    return
