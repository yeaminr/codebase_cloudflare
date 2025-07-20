import secrets
import string
import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException

from runner.src import cloudflare_test_service, main
from runner.src import auth_service
from runner.src import snow_service
from runner.src import github_service
from runner.src import working_dir as wd
from runner.src import terraform_service
from runner.src import cloudflare_token_service
from runner.src import cert_service, mtls_zero_trust_service
from runner.src import api_constant
from runner.src import exceptions
from runner.src.model import EnvironmentModel, InputModel, TestInputModel
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src import txt_record_service
from runner.src import validate_service


client = TestClient(main.app)


# Fastapi Mocks
def auth_service_account_run_mock_success(req):
    return JWTTokenInfo(
        authorized=True,
        repo_name=api_constant.AUTHORIZED_ACCOUNT_REPOS[0],
        org_name="org_name",
        branch_name="branch_name",
    )


def snow_service_verify_change_request_mock_success(req):
    return "CHG123456"


def auth_service_token_endpoint_run_mock_success(req):
    return JWTTokenInfo(
        authorized=True,
        repo_name=api_constant.AUTHORIZED_TOKEN_REPOS[0],
        org_name="org_name",
        branch_name="branch_name",
    )


def auth_service_run_mock_success(req):
    return JWTTokenInfo(
        authorized=True,
        repo_name="repo_name",
        org_name="org_name",
        branch_name="branch_name",
    )


@pytest.fixture
def mock_test_inputs():
    return TestInputModel(
        fqdn="www.example.com",
        report_inputs=TestInputModel.ReportInputs(
            tenant_repo="test_repo", github_run_id="12345"
        ),
        log_level="warning",
        test_tags="test_tag",
    )


def auth_service_run_mock_not_authorized(req):
    return None


# Tests
def test_health():
    response = client.get("/runner/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_root():
    response = client.get("/")
    assert response.status_code == 404


def test_endpoints_success(monkeypatch, mock_test_inputs):
    auth_header = {"x-github-auth-header": "Bearer dummy_token"}
    main.app.dependency_overrides[auth_service.verify_token] = (
        auth_service_account_run_mock_success
    )
    main.app.dependency_overrides[snow_service.verify_change_request] = (
        snow_service_verify_change_request_mock_success
    )
    monkeypatch.setattr(
        cloudflare_token_service,
        "set_cloudflare_scoped_token",
        lambda x: (["tokenid"], "dummy_token"),
    )
    monkeypatch.setattr(
        auth_service,
        "verify_repo_action",
        verify_repo_action_mock_success,
    )
    monkeypatch.setattr(
        main,
        "runner",
        runner_account_mock_success,
    )
    # Account API - GET
    account_response = client.get("/runner/account/dev?req=token", headers=auth_header)
    assert account_response.status_code == 200
    assert account_response.json() == {"status": "ok"}
    # Account API - UPDATE
    account_response = client.post(
        "/runner/account/dev?req=token&change_number=CHG123456", headers=auth_header
    )
    assert account_response.status_code == 200
    assert account_response.json() == {"status": "ok"}

    main.app.dependency_overrides[auth_service.verify_token] = (
        auth_service_run_mock_success
    )

    monkeypatch.setattr(
        main,
        "runner",
        runner_mock_success,
    )

    # Zone API - GET
    zone_response = client.get(
        "/runner/zone/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert zone_response.status_code == 200
    assert zone_response.json() == {"status": "ok"}
    # Zone API - UPDATE
    zone_response = client.post(
        "/runner/zone/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert zone_response.status_code == 200
    assert zone_response.json() == {"status": "ok"}

    # CDN API - GET
    cdn_response = client.get(
        "/runner/cdn/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert cdn_response.status_code == 200
    assert cdn_response.json() == {"status": "ok"}
    # CDN API - UPDATE
    cdn_response = client.post(
        "/runner/cdn/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert cdn_response.status_code == 200
    assert cdn_response.json() == {"status": "ok"}

    # Security API - GET
    security_response = client.get(
        "/runner/security/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert security_response.status_code == 200
    assert security_response.json() == {"status": "ok"}
    # Security API - UPDATE
    security_response = client.post(
        "/runner/security/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert security_response.status_code == 200
    assert security_response.json() == {"status": "ok"}

    # TLS API - GET
    tls_response = client.get(
        "/runner/tls/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert tls_response.status_code == 200
    assert tls_response.json() == {"status": "ok"}
    # TLS API - UPDATE
    tls_response = client.post(
        "/runner/tls/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert tls_response.status_code == 200
    assert tls_response.json() == {"status": "ok"}

    # Zone Certificate API - GET
    monkeypatch.setattr(cert_service, "get_cert", runner_mock_success)
    certificate_response = client.get(
        "/runner/cert/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert certificate_response.status_code == 200
    assert certificate_response.json() == {"status": "ok"}

    # app_list API - GET
    app_list_response = client.get(
        "/runner/app_list/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert app_list_response.status_code == 200
    assert app_list_response.json() == {"status": "ok"}
    # app_list API - UPDATE
    app_list_response = client.post(
        "/runner/app_list/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert app_list_response.status_code == 200
    assert app_list_response.json() == {"status": "ok"}

    # Zone Certificate API - UPDATE
    monkeypatch.setattr(cert_service, "update_cert", runner_mock_success)
    certificate_response = client.post(
        "/runner/cert/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert certificate_response.status_code == 200
    assert certificate_response.json() == {"status": "ok"}

    # mTLS API - GET
    monkeypatch.setattr(mtls_zero_trust_service, "get_mtls", mtls_mock_success)
    mtls_response = client.get(
        "/runner/mtls/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert mtls_response.status_code == 200
    assert mtls_response.json() == {"status": "ok"}

    # mtls API - UPDATE
    monkeypatch.setattr(mtls_zero_trust_service, "update_mtls", mtls_mock_success)
    mtls_response = client.post(
        "/runner/mtls/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert mtls_response.status_code == 200
    assert mtls_response.json() == {"status": "ok"}

    # Zone Workers API - GET
    certificate_response = client.get(
        "/runner/workers/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert certificate_response.status_code == 200
    assert certificate_response.json() == {"status": "ok"}

    # Zone Workers API - UPDATE
    certificate_response = client.post(
        "/runner/workers/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert certificate_response.status_code == 200
    assert certificate_response.json() == {"status": "ok"}

    # Validate API - GET
    monkeypatch.setattr(
        validate_service,
        "main",
        lambda x, y: {
            "status": "success",
            "message": "zone yaml is valid",
        },
    )
    valid_response = client.get(
        "/runner/validate/zone/dev?req=token&fqdn=www.example.com&change_number=CHG123456", headers=auth_header
    )
    assert valid_response.status_code == 200
    assert valid_response.json() == {
        "status": "success",
        "message": "zone yaml is valid",
    }

    # cf-terraforming API - GET
    return_obj = {
        "cloudflare_record": {
            "import_output": "import_stdout",
            "new_resources": "new_resource_ids",
            "generate_output": "generate_stdout",
        }
    }
    monkeypatch.setattr(
        terraform_service,
        "cf_terraforming",
        lambda x, y: return_obj,
    )
    cf_terraforming_response = client.get(
        "/runner/cf-terraforming/dev?req=token&fqdn=www.example.com&resource_type=cloudflare_record",
        headers=auth_header,
    )
    assert cf_terraforming_response.status_code == 200
    assert cf_terraforming_response.json() == return_obj

    monkeypatch.setattr(
        cloudflare_test_service,
        "create_test_session",
        runner_test_mock_success,
    )

    # Test API - POST
    test_response = client.post(
        "/runner/test/dev?req=token",
        headers=auth_header,
        json=mock_test_inputs.model_dump(),
    )

    assert test_response.status_code == 200
    assert test_response.json() == {"status": "ok"}

    # Rotate API - POST
    monkeypatch.setattr(cloudflare_token_service, "rotate_cloudflare_initial_token", rotate_cloudflare_initial_token_mock_success)
    rotate_response = client.post(
        "/runner/account/dev/rotate?req=token",
        headers=auth_header,
    )
    assert rotate_response.status_code == 200


def test_endpoints_authentication_failure(monkeypatch, mock_test_inputs):
    auth_header = {"x-github-auth-header": "Bearer dummy_token"}
    main.app.dependency_overrides[auth_service.verify_token] = (
        auth_service_run_mock_not_authorized
    )
    main.app.dependency_overrides[snow_service.verify_change_request] = (
        snow_service_verify_change_request_mock_success
    )
    monkeypatch.setattr(
        main,
        "runner",
        runner_mock_success,
    )
    # GET Requests
    # Account API - GET
    account_response = client.get("/runner/account/dev?req=token", headers=auth_header)
    assert account_response.status_code == 401
    assert account_response.json() == {"detail": "Not Authorized"}
    # Zone API - GET
    zone_response = client.get(
        "/runner/zone/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert zone_response.status_code == 401
    assert zone_response.json() == {"detail": "Not Authorized"}
    # CDN API - GET
    cdn_response = client.get(
        "/runner/cdn/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert cdn_response.status_code == 401
    assert cdn_response.json() == {"detail": "Not Authorized"}
    # Security API - GET
    security_response = client.get(
        "/runner/security/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert security_response.status_code == 401
    assert security_response.json() == {"detail": "Not Authorized"}
    # TLS API - GET
    tls_response = client.get(
        "/runner/tls/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert tls_response.status_code == 401
    assert tls_response.json() == {"detail": "Not Authorized"}

    # POST Requests
    # Account API - UPDATE
    account_response = client.post(
        "/runner/account/dev?req=token&change_number=CHG123456", headers=auth_header
    )
    assert account_response.status_code == 401
    assert account_response.json() == {"detail": "Not Authorized"}
    # Zone API - UPDATE
    zone_response = client.post(
        "/runner/zone/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert zone_response.status_code == 401
    assert zone_response.json() == {"detail": "Not Authorized"}
    # CDN API - UPDATE
    cdn_response = client.post(
        "/runner/cdn/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert cdn_response.status_code == 401
    assert cdn_response.json() == {"detail": "Not Authorized"}
    # Security API - UPDATE
    security_response = client.post(
        "/runner/security/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert security_response.status_code == 401
    assert security_response.json() == {"detail": "Not Authorized"}
    # TLS API - UPDATE
    tls_response = client.post(
        "/runner/tls/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert tls_response.status_code == 401
    assert tls_response.json() == {"detail": "Not Authorized"}
    # Zone Certificate API - GET
    certificate_response = client.get(
        "/runner/cert/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert certificate_response.status_code == 401
    assert certificate_response.json() == {"detail": "Not Authorized"}
    # Zone Certificate API - UPDATE
    certificate_response = client.post(
        "/runner/cert/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert certificate_response.status_code == 401
    assert certificate_response.json() == {"detail": "Not Authorized"}
    # Zone mTLS API - GET
    certificate_response = client.get(
        "/runner/mtls/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert certificate_response.status_code == 401
    assert certificate_response.json() == {"detail": "Not Authorized"}
    # Zone mTLS API - UPDATE
    certificate_response = client.post(
        "/runner/mtls/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert certificate_response.status_code == 401
    assert certificate_response.json() == {"detail": "Not Authorized"}
    # Zone Workers API - GET
    certificate_response = client.get(
        "/runner/workers/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert certificate_response.status_code == 401
    assert certificate_response.json() == {"detail": "Not Authorized"}
    # Zone Workers API - UPDATE
    certificate_response = client.post(
        "/runner/workers/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert certificate_response.status_code == 401
    assert certificate_response.json() == {"detail": "Not Authorized"}
    # App List API - GET
    app_list_response = client.get(
        "/runner/app_list/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert app_list_response.status_code == 401
    assert app_list_response.json() == {"detail": "Not Authorized"}
    # App List API - UPDATE
    app_list_response = client.post(
        "/runner/app_list/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert app_list_response.status_code == 401
    assert app_list_response.json() == {"detail": "Not Authorized"}
    # Validate API - GET
    valid_response = client.get(
        "/runner/validate/zone/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert valid_response.status_code == 401
    assert valid_response.json() == {"detail": "Not Authorized"}

    # cf-terraforming API - GET
    cf_terraforming_response = client.get(
        "/runner/cf-terraforming/dev?req=token&fqdn=www.example.com&resource_type=cloudflare_record",
        headers=auth_header,
    )
    assert cf_terraforming_response.status_code == 401
    assert cf_terraforming_response.json() == {"detail": "Not Authorized"}

    # Test API - POST
    test_response = client.post(
        "/runner/test/dev?req=token",
        headers=auth_header,
        json=mock_test_inputs.model_dump(),
    )
    assert test_response.status_code == 401
    assert test_response.json() == {"detail": "Not Authorized"}


def test_endpoints_authorization_failure(monkeypatch, mock_test_inputs):
    auth_header = {"x-github-auth-header": "Bearer dummy_token"}
    main.app.dependency_overrides[auth_service.verify_token] = (
        auth_service_run_mock_success
    )
    main.app.dependency_overrides[snow_service.verify_change_request] = (
        snow_service_verify_change_request_mock_success
    )
    monkeypatch.setattr(
        auth_service,
        "verify_repo_action",
        lambda x, y: False,
    )
    # Account API - GET
    account_response = client.get("/runner/account/dev?req=token", headers=auth_header)
    assert account_response.status_code == 403
    assert account_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="plan",
            config_type="account",
        )
    }
    # Zone API - UPDATE
    account_response = client.post(
        "/runner/account/dev?req=token&change_number=CHG123456",
        headers=auth_header,
    )
    assert account_response.status_code == 403
    assert account_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="apply",
            config_type="account",
        )
    }
    # Zone API - GET
    zone_response = client.get(
        "/runner/zone/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert zone_response.status_code == 403
    assert zone_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="plan",
            config_type="zone",
        )
    }
    # Zone API - UPDATE
    zone_response = client.post(
        "/runner/zone/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert zone_response.status_code == 403
    assert zone_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="apply",
            config_type="zone",
        )
    }
    # Zone CDN API - GET
    cdn_response = client.get(
        "/runner/cdn/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert cdn_response.status_code == 403
    assert cdn_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="plan",
            config_type="cdn",
        )
    }
    # Zone CDN API - UPDATE
    cdn_response = client.post(
        "/runner/cdn/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert cdn_response.status_code == 403
    assert cdn_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="apply",
            config_type="cdn",
        )
    }
    # Zone Security API - GET
    security_response = client.get(
        "/runner/security/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert security_response.status_code == 403
    assert security_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="plan",
            config_type="security",
        )
    }
    # Zone Security API - UPDATE
    security_response = client.post(
        "/runner/security/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert security_response.status_code == 403
    assert security_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="apply",
            config_type="security",
        )
    }
    # Zone TLS API - GET
    tls_response = client.get(
        "/runner/tls/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert tls_response.status_code == 403
    assert tls_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="plan",
            config_type="tls",
        )
    }
    # Zone TLS API - UPDATE
    tls_response = client.post(
        "/runner/tls/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert tls_response.status_code == 403
    assert tls_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="apply",
            config_type="tls",
        )
    }
    # Zone Cert API - GET
    cert_response = client.get(
        "/runner/cert/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert cert_response.status_code == 403
    assert cert_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="plan",
            config_type="cert",
        )
    }
    # Zone Cert API - UPDATE
    cert_response = client.post(
        "/runner/cert/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert cert_response.status_code == 403
    assert cert_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="apply",
            config_type="cert",
        )
    }
    # Zone mTLS API - GET
    certificate_response = client.get(
        "/runner/mtls/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert certificate_response.status_code == 403
    assert certificate_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="plan",
            config_type="mtls",
        )
    }

    # Zone mTLS API - UPDATE
    certificate_response = client.post(
        "/runner/mtls/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert certificate_response.status_code == 403
    assert certificate_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="apply",
            config_type="mtls",
        )
    }
    # Zone Workers API - GET
    certificate_response = client.get(
        "/runner/workers/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert certificate_response.status_code == 403
    assert certificate_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="plan",
            config_type="workers",
        )
    }

    # Zone Workers API - UPDATE
    certificate_response = client.post(
        "/runner/workers/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert certificate_response.status_code == 403
    assert certificate_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="apply",
            config_type="workers",
        )
    }
    # Zone App List API - GET
    certificate_response = client.get(
        "/runner/app_list/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert certificate_response.status_code == 403
    assert certificate_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="plan",
            config_type="app_list",
        )
    }

    # Zone App List API - UPDATE
    certificate_response = client.post(
        "/runner/app_list/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert certificate_response.status_code == 403
    assert certificate_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="apply",
            config_type="app_list",
        )
    }
    # Test API - POST
    test_response = client.post(
        "/runner/test/dev?req=token",
        headers=auth_header,
        json=mock_test_inputs.model_dump(),
    )

    assert test_response.status_code == 403
    assert test_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="plan",
            config_type="zone",
        )
    }
    # Validate API - GET
    valid_response = client.get(
        "/runner/validate/zone/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert valid_response.status_code == 403
    assert valid_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="validate",
            config_type="zone",
        )
    }

    # cf-terraforming API - GET
    cf_terraforming_response = client.get(
        "/runner/cf-terraforming/dev?req=token&fqdn=www.example.com&resource_type=cloudflare_record",
        headers=auth_header,
    )
    assert cf_terraforming_response.status_code == 403
    assert cf_terraforming_response.json() == {
        "detail": api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
            repo_name="repo_name",
            branch="branch_name",
            action="plan",
            config_type="zone",
        )
    }


def test_cert_service_get_cert_failure(monkeypatch):
    auth_header = {"x-github-auth-header": "Bearer dummy_token"}
    main.app.dependency_overrides[auth_service.verify_token] = (
        auth_service_run_mock_success
    )
    monkeypatch.setattr(
        auth_service,
        "verify_repo_action",
        verify_repo_action_mock_success,
    )
    monkeypatch.setattr(
        cloudflare_token_service,
        "set_cloudflare_scoped_token",
        lambda x: (["tokenid"], "dummy_token"),
    )

    # Zone Certificate API - GET CertificateServiceException Exception
    monkeypatch.setattr(cert_service, "get_cert", mock_certificate_service_exception)
    certificate_response = client.get(
        "/runner/cert/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert certificate_response.status_code == 500
    assert certificate_response.json() == {
        "detail": "500 Error: Error running Cert service: Test exception"
    }

    # Zone Certificate API - UPDATE CertificateServiceException Exception
    monkeypatch.setattr(cert_service, "update_cert", mock_certificate_service_exception)
    certificate_response = client.post(
        "/runner/cert/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert certificate_response.status_code == 500
    assert certificate_response.json() == {
        "detail": "500 Error: Error running Cert service: Test exception"
    }

    # Zone Certificate API - GET General Exception
    monkeypatch.setattr(cert_service, "get_cert", mock_exception)
    certificate_response = client.get(
        "/runner/cert/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert certificate_response.status_code == 500
    assert certificate_response.json() == {
        "detail": "Error running Cert service: Test exception"
    }

    # Zone Certificate API - UPDATE General Exception
    monkeypatch.setattr(cert_service, "update_cert", mock_exception)
    certificate_response = client.post(
        "/runner/cert/dev?req=token&fqdn=www.example.com&change_number=CHG123456",
        headers=auth_header,
    )
    assert certificate_response.status_code == 500
    assert certificate_response.json() == {
        "detail": "Error running Cert service: Test exception"
    }


def test_runner(monkeypatch):
    monkeypatch.setattr(
        wd,
        "create_dir",
        wd_create_dir_success,
    )
    monkeypatch.setattr(
        wd,
        "delete_dir",
        wd_delete_dir_success,
    )
    monkeypatch.setattr(
        github_service,
        "main",
        github_service_main_mock_success,
    )
    monkeypatch.setattr(
        terraform_service,
        "run",
        terraform_service_run_mock_success,
    )
    monkeypatch.setattr(
        terraform_service,
        "terraform_output",
        terraform_output_mock_success,
    )
    monkeypatch.setattr(
        txt_record_service,
        "process_txt_record",
        update_txt_record_mock_success,
    )
    jwt_token_info = JWTTokenInfo(
        repo_name="repo_name",
        org_name="org_name",
        branch_name="branch_name",
        authorized=True,
    )
    input_model = InputModel(
        environment=EnvironmentModel.dev,
        fqdn="example.com",
        config_type="zone",
        action="plan",
    )
    # Test main.runner happy flow
    response = main.runner(jwt_token_info=jwt_token_info, input_model=input_model)
    assert response == {"detail": {"plan": "success"}}

    # Test main.runner when TXT record update (txt_record_service.process_txt_record) is thrown exception
    monkeypatch.setattr(
        txt_record_service,
        "process_txt_record",
        process_txt_record_mock_exception,
    )
    input_model.action = "apply"
    with pytest.raises(HTTPException):
        main.runner(jwt_token_info=jwt_token_info, input_model=input_model)

    # Test main.runner when terraform_service.run is thrown exception
    monkeypatch.setattr(
        terraform_service,
        "run",
        terraform_service_main_mock_exception,
    )
    with pytest.raises(HTTPException):
        main.runner(jwt_token_info=jwt_token_info, input_model=input_model)

    # Test main.runner when github_service.main is thrown exception
    monkeypatch.setattr(
        github_service,
        "main",
        github_service_main_mock_exception,
    )
    with pytest.raises(HTTPException):
        main.runner(jwt_token_info=jwt_token_info, input_model=input_model)


# Mocks
def mock_exception(*args, **kwargs):
    raise ValueError("Test exception")  # throw some random exception/error


def mock_certificate_service_exception(*args, **kwargs):
    raise exceptions.CertificateServiceInvalidCertException(
        "Test exception"
    )  # throw child exception of CertificateServiceException


def runner_account_mock_success(jwt_token_info: JWTTokenInfo, input_model: InputModel):
    return {"status": "ok"}


def runner_mock_success(jwt_token_info: JWTTokenInfo, input_model: InputModel):
    return {"status": "ok"}


def runner_test_mock_success(
    jwt_token_info: JWTTokenInfo, input_model: InputModel, test_inputs: TestInputModel
):
    return {"status": "ok"}


def wd_create_dir_success():
    return api_constant.WORKING_DIR_PREFIX + "".join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(10)
    )


def wd_delete_dir_success(cwd):
    return None


def github_service_main_mock_success(
    jwt_token_info: JWTTokenInfo,
    input_model: InputModel,
    working_dir: str,
):
    return None


def terraform_service_run_mock_success(input_model: InputModel, working_dir: str):
    return {"plan": "success"}


def terraform_output_mock_success(cwd, verification_keys):
    return "12345-67890"


def helpers_get_zone_name_from_yaml_success(cwd):
    return "example.com"


def update_txt_record_mock_success(fqdn, txt_record_name, txt_record_value):
    return None


def github_service_main_mock_exception(jwt_info, payload, cwd):
    raise Exception("Test exception")


def terraform_service_main_mock_exception(payload, cwd):
    raise Exception("Test exception")


def process_txt_record_mock_exception(zone, txt_record_name, txt_record_value):
    raise Exception("Test exception")


def verify_repo_action_mock_success(jwt_token_info, input_model):
    return True


def add_zone_to_domain_group_mock_success(environment: str, fqdn: str):
    return {"status": "ok"}


def mtls_mock_success(jwt_token_info, input_model):
    return {"status": "ok"}

def rotate_cloudflare_initial_token_mock_success(environment: str):
    return True