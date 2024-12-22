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
        venafi_service.refresh_venafi_cert({}, "env", "signer", "tso", 10, [])

    # IDP private key is not set
    with pytest.raises(VenafiServiceException):
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "env",
            "signer",
            "tso",
            10,
            [],
        )

    # Error - env is prod but signer is not ext-ev
    monkeypatch.setattr(venafi_service.api_constant, "idp_private_key", "key")
    with pytest.raises(VenafiServiceException):
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "prod",
            "ext",
            "tso",
            10,
            [],
        )

    # Signer is not provided and env is prod
    with pytest.raises(VenafiServiceException):
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "prod",
            None,
            "tso",
            10,
            [],
        )

    # Signer is not provided and env is not prod
    with pytest.raises(VenafiServiceException):
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "dev",
            None,
            "tso",
            10,
            [],
        )

    # Signer is invalid
    with pytest.raises(VenafiServiceException):
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "prod",
            "invalid",
            "tso",
            10,
            [],
        )

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
            "env",
            "ext",
            "tso",
            10,
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
    with pytest.raises(VenafiServiceException):
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "prod",
            "ext",
            "tso",
            10,
            [],
        )

    # Invalid response - certificatedata is None and statuscode is 400
    # monkeypatch.setattr(venafi_service.api_constant, "idp_private_key", "key")
    monkeypatch.setattr(
        cbacert,
        "refresh",
        lambda *args: {"certificatedata": None, "statuscode": 400},
    )
    with pytest.raises(VenafiServiceException):
        venafi_service.refresh_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "prod",
            "ext",
            "tso",
            10,
            [],
        )


def test_retrieve_venafi_cert(monkeypatch):
    # CSR input is invalid
    with pytest.raises(VenafiServiceException):
        venafi_service.retrieve_venafi_cert({}, "tso")

    # IDP private key is not set
    with pytest.raises(VenafiServiceException):
        venafi_service.retrieve_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"}, "tso"
        )

    # Success
    monkeypatch.setattr(venafi_service.api_constant, "idp_private_key", "key")
    monkeypatch.setattr(
        cbacert,
        "retrieve",
        lambda *args: {"certificatedata": "dGVzdA==", "statuscode": 200},
    )
    assert (
        venafi_service.retrieve_venafi_cert(
            {"common_name": "test", "csr": "test", "id": "test"},
            "tso",
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
            {"common_name": "test", "csr": "test", "id": "test"}, "tso"
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
            {"common_name": "test", "csr": "test", "id": "test"}, "tso"
        )


# Mock
def mock_exception(*args, **kwargs):
    raise Exception("Mocked exception")
