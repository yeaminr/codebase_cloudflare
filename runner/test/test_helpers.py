import pytest
from runner.src import helpers, working_dir as wd
from runner.src import api_constant
from runner.src import hashicorp_vault_service
from runner.src import exceptions

def test_get_parameters_yaml() -> None:
    # Success case - Zone config
    config_type = "zone"
    cwd = wd.create_dir()
    with open(f"{cwd}/{config_type}_parameters.yml", "w", encoding="utf-8") as file:
        file.write("fqdn: example.com\n")
    result = helpers.get_parameters_yaml(cwd, config_type)
    assert result == {"fqdn": "example.com"}
    wd.delete_dir(cwd)

    # Failure case - File not found
    with pytest.raises(FileNotFoundError):
        helpers.get_parameters_yaml("invalid_path", config_type)

    # Failure case - cwd is None
    with pytest.raises(ValueError):
        helpers.get_parameters_yaml(None, config_type)

def test_check_initial_token(monkeypatch) -> None:
    monkeypatch.setattr(api_constant, "cf_initial_api_token", "cf_initial_api_token")
    monkeypatch.setattr('requests.get', mock_get)
    monkeypatch.setattr(hashicorp_vault_service, "get_vault_token", get_vault_token_mock)
    monkeypatch.setattr(hashicorp_vault_service, "read_secret_from_vault", read_secret_from_vault_mock)

    # Success case - Initial token exists
    assert helpers.check_initial_token(environment="dev") is not None

    # Failure case - Initial token does not exist
    monkeypatch.setattr(api_constant, "cf_initial_api_token", None)
    with pytest.raises(exceptions.TokenServiceMissingInitialApiTokenException):
        helpers.check_initial_token(environment="dev")


# Mock the requests.get method
def mock_get(url, headers, verify):
    class MockResponse:
        def json(self):
            return {'data': {'result': {'status': 'active'}}}
        def raise_for_status(self):
            pass
        def status_code(self):
            return 200
    return MockResponse()

def get_vault_token_mock() -> str:
    return "mock_vault_token"

def read_secret_from_vault_mock(url, vault_token, secret_to_read) -> str:
    return "mock_secret"
