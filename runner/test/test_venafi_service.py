from datetime import datetime, timedelta
import requests
import pytest
from cbacert import cbacert
from runner.src import venafi_service
from runner.src.exceptions import VenafiServiceException


# Test
def test_refresh_venafi_cert(monkeypatch):
    # CSR input is invalid
    with pytest.raises(VenafiServiceException):
        venafi_service.refresh_venafi_cert({}, "env", "signer", "tso", [])

    # IDP private key is not set
    monkeypatch.setattr(venafi_service.api_constant, "idp_private_key", "")
    with pytest.raises(VenafiServiceException) as exc_info:
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "env",
            "signer",
            "tso",
            [],
        )
    assert "Venafi private key is not set" in str(exc_info.value)

    # Client ID is not set
    monkeypatch.setattr(venafi_service.api_constant, "idp_private_key", "key")
    with pytest.raises(VenafiServiceException) as exc_info:
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "env",
            "signer",
            "tso",
            [],
        )
    assert "Venafi client ID is not set" in str(exc_info.value)

    # Signer is not provided
    monkeypatch.setattr(venafi_service.api_constant, "venafi_client_id", "client_id")
    with pytest.raises(VenafiServiceException) as exc_info:
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "prd",
            None,
            "tso",
            [],
        )
    assert "Invalid signer provided" in str(exc_info.value)

    # Signer is invalid
    with pytest.raises(VenafiServiceException) as exc_info:
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "prod",
            "invalid",
            "tso",
            [],
        )
    assert "Invalid signer provided" in str(exc_info.value)

    # Success
    # monkeypatch.setattr(venafi_service.api_constant, "idp_private_key", "key")
    monkeypatch.setattr(
        cbacert,
        "refresh",
        lambda *args: {"certificatedata": "dGVzdA==", "statuscode": 200},
    )
    assert (
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "prd",
            "ext",
            "tso",
            [],
        )
        == "test"
    )
    # Venafi Refresh error
    monkeypatch.setattr(
        cbacert,
        "refresh",
        mock_exception,
    )
    with pytest.raises(VenafiServiceException) as exc_info:
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "prod",
            "ext",
            "tso",
            [],
        )
    assert "Error issuing certificate from Venafi" in str(exc_info.value)

    # Invalid response - certificatedata is None and statuscode is 400
    # monkeypatch.setattr(venafi_service.api_constant, "idp_private_key", "key")
    monkeypatch.setattr(
        cbacert,
        "refresh",
        lambda *args: {"certificatedata": None, "statuscode": 400},
    )
    with pytest.raises(VenafiServiceException) as exc_info:
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "prod",
            "ext",
            "tso",
            [],
        )
    assert "Error issuing certificate from Venafi" in str(exc_info.value)


def test_retrieve_venafi_cert(monkeypatch):
    # CSR input is invalid
    with pytest.raises(VenafiServiceException):
        venafi_service.retrieve_venafi_cert({}, "tso", "dev")

    # IDP private key is not set
    with pytest.raises(VenafiServiceException):
        venafi_service.retrieve_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"}, "tso", "dev"
        )

    # Client ID is not set
    monkeypatch.setattr(venafi_service.api_constant, "idp_private_key", "key")
    with pytest.raises(VenafiServiceException):
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "env",
            "signer",
            "tso",
            [],
        )
    
    # Success
    monkeypatch.setattr(venafi_service.api_constant, "venafi_client_id", "client_id")
    monkeypatch.setattr(
        cbacert,
        "retrieve",
        lambda *args: {"certificatedata": "dGVzdA==", "statuscode": 200},
    )
    assert (
        venafi_service.retrieve_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "tso", "dev"
        )
        == "test"
    )
    # Success
    # monkeypatch.setattr(venafi_service.api_constant, "idp_private_key", "key")
    monkeypatch.setattr(
        cbacert,
        "retrieve",
        lambda *args: {"certificatedata": None, "statuscode": 400},
    )
    assert (
        venafi_service.retrieve_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"}, "tso", "dev"
        )
        is None
    )

    # Venafi retrieve error
    monkeypatch.setattr(
        cbacert,
        "retrieve",
        mock_exception,
    )
    with pytest.raises(VenafiServiceException):
        venafi_service.retrieve_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"}, "tso", "dev"
        )


# Mock
def mock_exception(*args, **kwargs):
    raise Exception("Mocked exception")
