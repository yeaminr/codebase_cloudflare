from datetime import datetime, timedelta
import pytest
import httpx
import base64
from fastapi import HTTPException
from runner.src.model import InputModel, CertOutputModel
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src import github_service
from runner.src import cloudflare_token_service
from runner.src import cert_service
from runner.src import exceptions
from runner.src import venafi_service
from cf.python.src import helpers


# Common Input
input_model = InputModel(
    environment="dev", action="plan", config_type="cert", fqdn="fqdn"
)
jwt_token_info = JWTTokenInfo(
    repo_name="repo_name",
    branch_name="abc",
    authorized=True,
    org_name="CBA-General",
)


# Test
def test_renew_cert():
    # Cert expires 30 days later - No renewal - Renewal period within 7 days
    cert_dict = {
        "certificates": [
            {
                "id": "id",
                "expires_on": (datetime.now() + timedelta(days=30)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
            }
        ],
    }
    assert not cert_service.renew_cert(cert_dict, 7)
    # Cert expires 5 days later - Renewal - Renewal period within 7 days
    cert_dict = {
        "certificates": [
            {
                "id": "id",
                "expires_on": (datetime.now() + timedelta(days=5)).strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ"
                ),
            }
        ],
    }
    assert cert_service.renew_cert(cert_dict, 7)
    # Invalid cert
    cert_dict = {"certificates": []}
    with pytest.raises(exceptions.CertificateServiceInvalidCertException):
        cert_service.renew_cert(cert_dict, 7)


def test_plan_cert_csr_create_cert_upload(monkeypatch):
    # Success - CSR and Cert To be Created and Uploaded
    cert_parameters = """
certs:
    name: test
    common_name: new
    sans: [test1, test2]
    renew_time: 7
    tso: 0
"""
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: "token_store"
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(
        github_service, "get_file_content", lambda x, y: cert_parameters
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(helpers, "get_account_id", lambda x, y: "account_id")
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    monkeypatch.setattr(
        venafi_service,
        "retrieve_venafi_cert",
        lambda a, b: "certificate_string",
    )
    assert cert_service.plan_cert(input_model, jwt_token_info) == CertOutputModel(
        csr_status="to_be_created",
        cert_status="to_be_uploaded",
        common_name="new",
        sans=["test1", "test2"],
        venafi_status="to_be_created",
    )


def test_plan_cert_csr_exist_cert_upload(monkeypatch):
    # Success - CSR exist, Cert To be Created and Uploaded
    cert_parameters = """
certs:
    name: test
    common_name: test
    sans: [test1, test2]
    renew_time: 7
    tso: 0
"""
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: "token_store"
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(
        github_service, "get_file_content", lambda x, y: cert_parameters
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(helpers, "get_account_id", lambda x, y: "account_id")
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    monkeypatch.setattr(
        venafi_service,
        "retrieve_venafi_cert",
        lambda a, b: "certificate_string",
    )
    assert cert_service.plan_cert(input_model, jwt_token_info) == CertOutputModel(
        cert_status="to_be_uploaded",
        common_name="test",
        csr_status="exist",
        csr_id="csr_id",
        sans=["test1", "test2"],
        csr=base64.b64encode("csr_string".encode("utf-8")),
        venafi_status="exist",
    )


def test_plan_cert_csr_exist_cert_exist(monkeypatch):
    # Success - CSR exist and Cert exist - No renewal
    cert_parameters = """
certs:
    name: test
    common_name: test
    sans: [test1, test2]
    renew_time: 7
    tso: 0
"""
    cert_expiry_days = 30
    cert_expiry = (datetime.now() + timedelta(days=cert_expiry_days)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_csr",
        lambda x, y, z: {"certificates": [{"expires_on": cert_expiry}]},
    )
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: "token_store"
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(
        github_service, "get_file_content", lambda x, y: cert_parameters
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(helpers, "get_account_id", lambda x, y: "account_id")
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    monkeypatch.setattr(
        venafi_service,
        "retrieve_venafi_cert",
        lambda a, b: "certificate_string",
    )
    assert cert_service.plan_cert(input_model, jwt_token_info) == CertOutputModel(
        cert_status="exist",
        expiresin=cert_expiry,
        common_name="test",
        csr_status="exist",
        csr_id="csr_id",
        sans=["test1", "test2"],
        csr=base64.b64encode("csr_string".encode("utf-8")),
        venafi_status="exist",
    )


def test_plan_cert_csr_exist_cert_renewal(monkeypatch):
    # Success - CSR exist and Cert exist but within expiry renewal period
    cert_parameters = """
certs:
    name: test
    common_name: test
    sans: [test1, test2]
    renew_time: 7
    tso: 0
"""
    cert_expiry_days = 5
    cert_expiry = (datetime.now() + timedelta(days=cert_expiry_days)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_csr",
        lambda x, y, z: {"certificates": [{"expires_on": cert_expiry}]},
    )
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: "token_store"
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(
        github_service, "get_file_content", lambda x, y: cert_parameters
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(helpers, "get_account_id", lambda x, y: "account_id")
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    monkeypatch.setattr(
        venafi_service,
        "retrieve_venafi_cert",
        lambda a, b: "certificate_string",
    )
    assert cert_service.plan_cert(input_model, jwt_token_info) == CertOutputModel(
        cert_status="to_be_renewed",
        expiresin=cert_expiry,
        common_name="test",
        csr_status="exist",
        csr_id="csr_id",
        sans=["test1", "test2"],
        csr=base64.b64encode("csr_string".encode("utf-8")),
        venafi_status="exist",
    )


def test_plan_cert_delete_token_error(monkeypatch):
    cert_parameters = """
certs:
    name: test
    common_name: test
    sans: [test1, test2]
    renew_time: 7
    tso: 0
"""
    cert_expiry_days = 5
    cert_expiry = (datetime.now() + timedelta(days=cert_expiry_days)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_csr",
        lambda x, y, z: {"certificates": [{"expires_on": cert_expiry}]},
    )
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: "token_store"
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(
        github_service, "get_file_content", lambda x, y: cert_parameters
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(helpers, "get_account_id", lambda x, y: "account_id")
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    monkeypatch.setattr(
        venafi_service,
        "retrieve_venafi_cert",
        lambda a, b: "certificate_string",
    )
    # Error - Delete all tokens failed
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", mock_delete_all_tokens
    )
    assert cert_service.plan_cert(input_model, jwt_token_info) == CertOutputModel(
        cert_status="to_be_renewed",
        expiresin=cert_expiry,
        common_name="test",
        csr_status="exist",
        csr_id="csr_id",
        sans=["test1", "test2"],
        csr=base64.b64encode("csr_string".encode("utf-8")),
        venafi_status="exist",
        error="Error",
    )


def test_process_cert_csr_create_cert_upload(monkeypatch):
    # Success - CSR, Cert Created and Uploaded
    cert_parameters = """
certs:
    name: test
    common_name: new
    sans: [test1, test2]
    renew_time: 7
    tso: 0
    """
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: "token_store"
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(
        github_service, "get_file_content", lambda x, y: cert_parameters
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(helpers, "get_account_id", lambda x, y: "account_id")
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    monkeypatch.setattr(
        venafi_service,
        "refresh_venafi_cert",
        lambda a, b, c, d, e, f: "certificate_string",
    )
    assert cert_service.process_cert(input_model, jwt_token_info) == CertOutputModel(
        csr=base64.b64encode("csr_string".encode("utf-8")),
        cert_status="created",
        expiresin="cert_expiry",
        common_name="test",
        csr_status="created",
        csr_id="csr_id",
        sans=["test1", "test2"],
        venafi_status="created",
    )


def test_process_cert_csr_exist_cert_upload(monkeypatch):
    # Success - CSR exist, Cert Created and Uploaded
    cert_parameters = """
certs:
    name: test
    common_name: test
    sans: [test1, test2]
    renew_time: 7
    tso: 0
"""
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: "token_store"
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(
        github_service, "get_file_content", lambda x, y: cert_parameters
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(helpers, "get_account_id", lambda x, y: "account_id")
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    monkeypatch.setattr(
        venafi_service,
        "refresh_venafi_cert",
        lambda a, b, c, d, e, f: "certificate_string",
    )
    assert cert_service.process_cert(input_model, jwt_token_info) == CertOutputModel(
        csr=base64.b64encode("csr_string".encode("utf-8")),
        cert_status="created",
        expiresin="cert_expiry",
        common_name="test",
        csr_status="exist",
        csr_id="csr_id",
        sans=["test1", "test2"],
        venafi_status="refreshed",
    )


def test_process_cert_csr_exist_cert_exist(monkeypatch):
    # Success - CSR exist and Cert exist - No renewal
    cert_parameters = """
certs:
    name: test
    common_name: test
    sans: [test1, test2]
    renew_time: 7
    tso: 0
"""
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: "token_store"
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(
        github_service, "get_file_content", lambda x, y: cert_parameters
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(helpers, "get_account_id", lambda x, y: "account_id")
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    monkeypatch.setattr(
        venafi_service,
        "refresh_venafi_cert",
        lambda a, b, c, d, e, f: "certificate_string",
    )
    cert_expiry_days = 30
    cert_expiry = (datetime.now() + timedelta(days=cert_expiry_days)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_csr",
        lambda x, y, z: {"certificates": [{"expires_on": cert_expiry}]},
    )
    assert cert_service.process_cert(input_model, jwt_token_info) == CertOutputModel(
        csr=base64.b64encode("csr_string".encode("utf-8")),
        cert_status="exist",
        expiresin=cert_expiry,
        common_name="test",
        csr_status="exist",
        csr_id="csr_id",
        sans=["test1", "test2"],
        venafi_status="exist",
    )


def test_process_cert_csr_exist_cert_renewal(monkeypatch):
    # Success - CSR exist and Cert exist but within expiry renewal period
    cert_parameters = """
certs:
    name: test
    common_name: test
    sans: [test1, test2]
    renew_time: 7
    tso: 0
"""
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: "token_store"
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(
        github_service, "get_file_content", lambda x, y: cert_parameters
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(helpers, "get_account_id", lambda x, y: "account_id")
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    monkeypatch.setattr(
        venafi_service,
        "refresh_venafi_cert",
        lambda a, b, c, d, e, f: "certificate_string",
    )
    cert_expiry_days = 5
    cert_expiry = (datetime.now() + timedelta(days=cert_expiry_days)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_csr",
        lambda x, y, z: {"certificates": [{"expires_on": cert_expiry}]},
    )
    assert cert_service.process_cert(input_model, jwt_token_info) == CertOutputModel(
        csr=base64.b64encode("csr_string".encode("utf-8")),
        cert_status="renewed",
        expiresin="cert_expiry",
        common_name="test",
        csr_status="exist",
        csr_id="csr_id",
        sans=["test1", "test2"],
        venafi_status="exist",
    )


def test_process_cert_error(monkeypatch):
    # Error - Delete all tokens failed
    cert_parameters = """
certs:
    name: test
    common_name: test
    sans: [test1, test2]
    renew_time: 7
    tso: 0
"""
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: "token_store"
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(
        github_service, "get_file_content", lambda x, y: cert_parameters
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: None
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(helpers, "get_account_id", lambda x, y: "account_id")
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    monkeypatch.setattr(
        venafi_service,
        "refresh_venafi_cert",
        lambda a, b, c, d, e, f: "certificate_string",
    )
    cert_expiry_days = 30
    cert_expiry = (datetime.now() + timedelta(days=cert_expiry_days)).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    monkeypatch.setattr(
        cert_service,
        "get_cf_zone_cert_by_csr",
        lambda x, y, z: {"certificates": [{"expires_on": cert_expiry}]},
    )
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", mock_delete_all_tokens
    )
    assert cert_service.process_cert(input_model, jwt_token_info) == CertOutputModel(
        csr=base64.b64encode("csr_string".encode("utf-8")),
        cert_status="exist",
        expiresin=cert_expiry,
        common_name="test",
        csr_status="exist",
        csr_id="csr_id",
        sans=["test1", "test2"],
        venafi_status="exist",
        error="Error",
    )
    # Error - CSR required parameter "common_name" missing
    cert_parameters = """
certs:
    name: test
    sans: [test1, test2]
    renew_time: 7
    tso: 0
"""
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.process_cert(input_model, jwt_token_info)
    # Error - CSR optional parameter values not in allowed list
    cert_parameters = """
certs:
    name: test
    common_name: test
    country: invalid
    sans: [test1, test2]
    renew_time: 7
    tso: 0
"""
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.process_cert(input_model, jwt_token_info)
    # Error - Cert required parameter "tso" missing
    cert_parameters = """
certs:
    name: test
    common_name: test
    sans: [test1, test2]
    renew_time: 7
"""
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.process_cert(input_model, jwt_token_info)
    # Error - Github service get_file_content failed
    monkeypatch.setattr(github_service, "get_file_content", mock_get_file_content)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.process_cert(input_model, jwt_token_info)
    # Cloudflare api token None
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token", lambda x: None
    )
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.process_cert(input_model, jwt_token_info)


def test_create_cert(monkeypatch):
    monkeypatch.setattr(
        venafi_service,
        "refresh_venafi_cert",
        lambda a, b, c, d, e, f: None,
    )
    # Success scenario covered in test_process_cert
    # Failure scenario - Venafi refresh return None
    assert cert_service.create_cert("token", "dev", "zone_id", {}, {}) == None


def test_upload_cf_zone_certificate(monkeypatch):
    # Success scenario covered in test_process_cert
    # Failure scenario - Failed to upload certificate
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.upload_cf_zone_certificate(
            "token", "http_error", "csr_id", "cert_string"
        )


def test_list_cf_account_csr(monkeypatch):
    # Success scenario covered in test_process_cert
    # Failure scenario - HTTP error Failed to list account CSRs
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_account_csr("token", "http_error")

    # Failure scenario - "result" key missing
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_account_csr("token", "result_missing")

    # Result empty
    assert cert_service.list_cf_account_csr("token", "result_empty") == []

    # Result info missing
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_account_csr("token", "result_info_missing")


def test_list_cf_zone_certificates(monkeypatch):
    # Success scenario covered in test_process_cert
    # Failure scenario - HTTP error - Failed to list certificates
    monkeypatch.setattr(httpx, "get", mock_httpx_get)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_zone_certificates("token", "http_error")

    # Failure scenario - "result" key missing
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_zone_certificates("token", "result_missing")

    # Result empty
    assert cert_service.list_cf_zone_certificates("token", "result_empty") == []

    # Result info missing
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.list_cf_zone_certificates("token", "result_info_missing")


def test_get_cf_zone_cert_by_csr(monkeypatch):
    first_cert_expiry_days = 5
    first_cert_expiry = (
        datetime.now() + timedelta(days=first_cert_expiry_days)
    ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    second_cert_expiry_days = -5
    second_cert_expiry = (
        datetime.now() + timedelta(days=second_cert_expiry_days)
    ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    monkeypatch.setattr(
        cert_service,
        "list_cf_zone_certificates",
        lambda x, y: [
            {
                "certificates": [{"expires_on": first_cert_expiry, "id": "csr_id"}],
                "custom_csr_id": "csr_id",
            },
            {
                "certificates": [{"expires_on": second_cert_expiry, "id": "csr_id"}],
                "custom_csr_id": "csr_id",
            },
        ],
    )
    assert cert_service.get_cf_zone_cert_by_csr("token", "zone_id", "csr_id") == {
        "certificates": [{"expires_on": first_cert_expiry, "id": "csr_id"}],
        "custom_csr_id": "csr_id",
    }

    # # Failure scenario - "result" key missing
    # with pytest.raises(exceptions.CertificateServiceException):
    #     cert_service.get_cf_zone_cert_by_csr("token", "result_missing", "csr_id")


def test_generate_cf_account_csr(monkeypatch):
    # Success scenario covered in test_process_cert
    # Failure scenario - HTTP error - Failed to generate CSR
    monkeypatch.setattr(httpx, "post", mock_httpx_post)
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.generate_cf_account_csr("token", "http_error", "csr_input")

    # Failure scenario - "result" key missing
    with pytest.raises(exceptions.CertificateServiceException):
        cert_service.generate_cf_account_csr("token", "result_missing", "csr_input")


# Mock
def mock_delete_all_tokens(token_store, token):
    raise Exception("Error")


def mock_get_file_content(cert_input_url, working_dir):
    raise Exception("Error")


def mock_httpx_get(url, headers=None):
    if (
        url
        == "https://api.cloudflare.com/client/v4/accounts/account_id/custom_csrs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "sans": ["test1", "test2"],
                        "common_name": "test",
                        "id": "csr_id",
                        "csr": "csr_string",
                    }
                ],
                "result_info": {
                    "page": 1,
                    "per_page": 50,
                    "total_pages": 1,
                    "count": 1,
                    "total_count": 1,
                },
            },
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/accounts/result_missing/custom_csrs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={"result_missing": []},
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/accounts/result_empty/custom_csrs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={"result": []},
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/accounts/result_info_missing/custom_csrs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "sans": ["test1", "test2"],
                        "common_name": "test",
                        "id": "csr_id",
                        "csr": "csr_string",
                    }
                ]
            },
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/zone_id/ssl/certificate_packs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={
                "result": [],
                "result_info": {
                    "page": 1,
                    "per_page": 50,
                    "total_pages": 1,
                    "count": 0,
                    "total_count": 1,
                },
            },
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/cert_exist/ssl/certificate_packs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "certificates": [
                            {
                                "expires_on": "2025-12-12T23:59:59.000000Z",
                                "id": "csr_id",
                            }
                        ],
                        "custom_csr_id": "csr_id",
                    }
                ],
                "result_info": {
                    "page": 1,
                    "per_page": 50,
                    "total_pages": 1,
                    "count": 0,
                    "total_count": 1,
                },
            },
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/result_missing/ssl/certificate_packs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={"result_missing": []},
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/result_empty/ssl/certificate_packs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={"result": []},
            request=httpx.Request("GET", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/zones/result_info_missing/ssl/certificate_packs?page=1&per_page=50"
    ):
        return httpx.Response(
            200,
            json={
                "result": [
                    {
                        "sans": ["test1", "test2"],
                        "common_name": "test",
                        "id": "csr_id",
                        "csr": "csr_string",
                    }
                ]
            },
            request=httpx.Request("GET", "test"),
        )
    return httpx.Response(
        404,
        request=httpx.Request("GET", "test"),
    )


def mock_httpx_post(url, json, headers):
    if url == "https://api.cloudflare.com/client/v4/accounts/account_id/custom_csrs":
        return httpx.Response(
            200,
            json={
                "result": {
                    "sans": ["test1", "test2"],
                    "common_name": "test",
                    "id": "csr_id",
                    "csr": "csr_string",
                }
            },
            request=httpx.Request("POST", "test"),
        )
    elif (
        url
        == "https://api.cloudflare.com/client/v4/accounts/result_missing/custom_csrs"
    ):
        return httpx.Response(
            200,
            json={"result_missing": {}},
            request=httpx.Request("POST", "test"),
        )

    elif (
        url == "https://api.cloudflare.com/client/v4/zones/zone_id/custom_certificates"
    ):
        return httpx.Response(
            200,
            json={"result": {"expires_on": "cert_expiry", "id": "cert_id"}},
            request=httpx.Request("POST", "test"),
        )
    return httpx.Response(
        404,
        request=httpx.Request("POST", "test"),
    )
