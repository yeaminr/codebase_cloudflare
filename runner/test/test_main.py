import secrets
import string
import pytest
from fastapi.testclient import TestClient
from fastapi import HTTPException

from runner.src import main
from runner.src import auth_service
from runner.src import aws_service
from runner.src import github_service
from runner.src import working_dir as wd
from runner.src import terraform_service
from runner.src import cloudflare_token_service
from runner.src import api_constant
from runner.src.model import EnvironmentModel, InputModel
from runner.src.jwt_token_info import JWTTokenInfo


client = TestClient(main.app)


# Fastapi Mocks
def auth_service_run_mock_success(req):
    return JWTTokenInfo(
        authorized=True,
        repo_name="repo_name",
        org_name="org_name",
        branch_name="branch_name",
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


def test_endpoints_success(monkeypatch):
    auth_header = {"x-github-auth-header": "Bearer dummy_token"}
    main.app.dependency_overrides[auth_service.verify_token] = (
        auth_service_run_mock_success
    )
    monkeypatch.setattr(
        cloudflare_token_service,
        "set_cloudflare_scoped_token",
        set_cloudflare_scoped_token_mock_success,
    )
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "dummy_token")
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
    account_response = client.post("/runner/account/dev?req=token", headers=auth_header)
    assert account_response.status_code == 200
    assert account_response.json() == {"status": "ok"}

    monkeypatch.setattr(
        main,
        "runner",
        runner_mock_success,
    )

    monkeypatch.setattr(
        auth_service,
        "verify_repo_action",
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
        "/runner/zone/dev?req=token&fqdn=www.example.com", headers=auth_header
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
        "/runner/cdn/dev?req=token&fqdn=www.example.com", headers=auth_header
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
        "/runner/security/dev?req=token&fqdn=www.example.com", headers=auth_header
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
        "/runner/tls/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert tls_response.status_code == 200
    assert tls_response.json() == {"status": "ok"}

    # Account Token API - GET
    token_response = client.get(
        "/runner/account/dev/token?req=token", headers=auth_header
    )
    assert token_response.status_code == 200
    assert token_response.json() == {"token": "dummy_token", "id": "tokenid"}
    
    # Zone Token API - GET
    token_response = client.get(
        "/runner/zone/dev/token?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert token_response.status_code == 200
    assert token_response.json() == {"token": "dummy_token", "id": "tokenid"}


def test_endpoints_auth_failure(monkeypatch):
    auth_header = {"x-github-auth-header": "Bearer dummy_token"}
    main.app.dependency_overrides[auth_service.verify_token] = (
        auth_service_run_mock_not_authorized
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
    # Account Token API - GET
    token_response = client.get(
        "/runner/account/dev/token?req=token", headers=auth_header
    )
    assert token_response.status_code == 401
    assert token_response.json() == {"detail": "Not Authorized"}

    # Zone Token API - GET
    token_response = client.get(
        "/runner/zone/dev/token?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert token_response.status_code == 401
    assert token_response.json() == {"detail": "Not Authorized"}

    # POST Requests
    # Account API - UPDATE
    account_response = client.post("/runner/account/dev?req=token", headers=auth_header)
    assert account_response.status_code == 401
    assert account_response.json() == {"detail": "Not Authorized"}
    # Zone API - UPDATE
    zone_response = client.post(
        "/runner/zone/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert zone_response.status_code == 401
    assert zone_response.json() == {"detail": "Not Authorized"}
    # CDN API - UPDATE
    cdn_response = client.post(
        "/runner/cdn/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert cdn_response.status_code == 401
    assert cdn_response.json() == {"detail": "Not Authorized"}
    # Security API - UPDATE
    security_response = client.post(
        "/runner/security/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert security_response.status_code == 401
    assert security_response.json() == {"detail": "Not Authorized"}
    # TLS API - UPDATE
    tls_response = client.post(
        "/runner/tls/dev?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert tls_response.status_code == 401
    assert tls_response.json() == {"detail": "Not Authorized"}


def test_token_endpoint_token_none(monkeypatch):
    auth_header = {"x-github-auth-header": "Bearer dummy_token"}
    main.app.dependency_overrides[auth_service.verify_token] = (
        auth_service_run_mock_success
    )
    monkeypatch.setattr(
        cloudflare_token_service,
        "set_cloudflare_scoped_token",
        set_cloudflare_scoped_token_mock_success,
    )
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    # Account Token API - GET
    token_response = client.get(
        "/runner/account/dev/token?req=token", headers=auth_header
    )
    assert token_response.status_code == 404
    assert token_response.json() == {'detail': 'Cloudflare account scoped token not found'}

    # Zone Token API - GET
    token_response = client.get(
        "/runner/zone/dev/token?req=token&fqdn=www.example.com", headers=auth_header
    )
    assert token_response.status_code == 404
    assert token_response.json() == {'detail': 'Cloudflare zone scoped token not found'}


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
        aws_service,
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

    # Test main.runner when TXT record update (aws_service.process_txt_record) is thrown exception
    monkeypatch.setattr(
        aws_service,
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
def runner_account_mock_success(jwt_token_info: JWTTokenInfo, input_model: InputModel):
    return {"status": "ok"}

def runner_mock_success(jwt_token_info: JWTTokenInfo, input_model: InputModel):
    return {"status": "ok"}


def set_cloudflare_scoped_token_mock_success(input_model: InputModel):
    return ["tokenid"]


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


def terraform_service_run_mock_success(
    input_model: InputModel, working_dir: str
):
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

def verify_repo_action_mock_success(tenant_repo_name: str, cf_zone_name: str):
    return True
