import pytest
from runner.src import hashicorp_vault_service

#Unit tests for Hashicorp Vault Service
def test_get_vault_token(monkeypatch):
    # Fixture
    monkeypatch.setattr('requests.post', mock_post)

    # Call the function to test
    token = hashicorp_vault_service.get_vault_token()

    # Assertions
    assert token == 'mock_token'

    # Failure scenario
    monkeypatch.setattr('requests.post', mock_post_failure)
    with pytest.raises(Exception):
        hashicorp_vault_service.get_vault_token()

def test_read_secret_from_vault(monkeypatch):
    # Fixture
    monkeypatch.setattr('requests.get', mock_get)

    vault_secret = hashicorp_vault_service.read_secret_from_vault(
        full_url="https://vault.example.com/v1/secret/data/mysecret",
        vault_token="mock_token",
        secret_to_read="secret_to_read"
    )

    # Assertions - success scenario
    assert vault_secret != ""


# Mock the requests.post method
def mock_post(url, json, verify):
    class MockResponse:
        def json(self):
            return {'auth': {'client_token': 'mock_token'}}
        def raise_for_status(self):
            pass
    return MockResponse()

# Mock the requests.get method
def mock_get(url, headers, verify):
    class MockResponse:
        def json(self):
            return {'data': {'data': {'secret_to_read': 'mock_secret'}}}
        def raise_for_status(self):
            pass
    return MockResponse()

# Mock the requests.post method for failure scenario
def mock_post_failure(url, json, verify):
    class MockResponse:
       def json(self):
           return {'auth': {'client_token': 'mock_token'}}
       def raise_for_status(self):
           raise Exception("Failed to retrieve Vault token")
    return MockResponse()
