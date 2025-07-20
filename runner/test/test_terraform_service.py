import os
import pytest
from runner.src import helpers
from runner.src import terraform_service
from runner.src import api_constant
from runner.src import exceptions
from runner.src import working_dir as wd
from runner.src import cloudflare_token_service
from runner.src.model import InputModel


# Tests
def test_create_backend_file_success(monkeypatch) -> None:
    monkeypatch.setattr(api_constant, "state_bucket_name", "state_bucket_name")
    monkeypatch.setattr(
        api_constant, "state_lock_dynamodb_table", "state_lock_dynamodb_table"
    )
    terraform_service.create_backend_file(".", "test_key")
    with open("backend.tf", "r", encoding="UTF=8") as file:
        assert (
            file.read()
            == 'terraform {\n  backend "s3" {\n    bucket = "state_bucket_name"\n    key    = "test_key"\n    dynamodb_table = "state_lock_dynamodb_table"\n    region = "ap-southeast-2"\n  }\n}\n'
        )


def test_create_backend_file_none_values(monkeypatch) -> None:
    monkeypatch.setattr(api_constant, "state_bucket_name", None)
    # Test with None for state_bucket_name
    with pytest.raises(exceptions.TerraformServiceBackendException):
        terraform_service.create_backend_file(".", "test_key")
    monkeypatch.setattr(api_constant, "state_bucket_name", "state_bucket_name")
    monkeypatch.setattr(api_constant, "state_lock_dynamodb_table", None)
    # Test with None for state_lock_dynamodb_table
    with pytest.raises(exceptions.TerraformServiceBackendException):
        terraform_service.create_backend_file(".", "test_key")
    monkeypatch.setattr(
        api_constant, "state_lock_dynamodb_table", "state_lock_dynamodb_table"
    )
    # Test with None for state_key
    with pytest.raises(exceptions.TerraformServiceBackendException):
        terraform_service.create_backend_file(".", None)


def test_get_backend_key() -> None:
    # Test for account
    assert (
        terraform_service.get_backend_key(None, "account")
        == "account.terraform.tfstate"
    )
    # Test for fqdn - zone
    assert (
        terraform_service.get_backend_key("example.com.au", "zone")
        == "example.com.au/zone.terraform.tfstate"
    )
    # Test for fqdn - cdn
    assert (
        terraform_service.get_backend_key("example.com.au", "cdn")
        == "example.com.au/cdn/terraform.tfstate"
    )
    # Test for fqdn - security
    assert (
        terraform_service.get_backend_key("example.com.au", "security")
        == "example.com.au/security/terraform.tfstate"
    )
    # Test for fqdn - tls
    assert (
        terraform_service.get_backend_key("example.com.au", "tls")
        == "example.com.au/tls/terraform.tfstate"
    )
    # Test for invalid config type
    with pytest.raises(exceptions.TerraformServiceBackendException):
        terraform_service.get_backend_key("example.com.au", "invalid")


def test_terraform_init_plan_action_output(monkeypatch) -> None:
    monkeypatch.setattr(terraform_service, "get_backend_key", get_backend_key_mock)
    monkeypatch.setattr(
        terraform_service, "create_backend_file", create_backend_file_mock
    )
    # Test for init action
    monkeypatch.setattr(
        terraform_service, "run_terraform_command", lambda x, y: ( 0, "success", None)
    )
    assert terraform_service.terraform_init(
        "working_directory", "example.com.au", "zone"
    ) == (0, "success", None)
    # Test init reconfigure action
    monkeypatch.setattr(
        terraform_service, "run_terraform_command", lambda x, y: ( 0, "success", None)
    )
    assert terraform_service.terraform_init_reconfigure(
        "working_directory", "example.com.au", "zone"
    ) == (0, "success", None)
    # Test for output action
    assert terraform_service.terraform_output(
        "working_directory",
        "name",
    ) == (0, "success", None)
    # Test for plan action
    monkeypatch.setattr(
        terraform_service, "run_terraform_command", lambda x, y, z: ( 0, "success", None)
    )
    assert terraform_service.terraform_plan("working_directory", "account_id", "cf_api_token") == (
        0,
        "success",
        None,
    )
    # Test for apply action
    assert terraform_service.terraform_apply("working_directory", "account_id", "cf_api_token") == (
        0,
        "success",
        None,
    )


def test_run_success(monkeypatch) -> None:
    monkeypatch.setattr(wd, "copy_tf_files", copy_tf_files_mock)
    monkeypatch.setattr(
        terraform_service, "terraform_init", lambda x, y, z: (0, "success", None)
    )
    monkeypatch.setattr(
        terraform_service, "terraform_plan", lambda x, y, z: (0, "success", None)
    )

    monkeypatch.setattr(helpers, "check_initial_token", check_initial_token_mock)
    monkeypatch.setattr(
        cloudflare_token_service,
        "set_cloudflare_scoped_token",
        lambda x : (["tokenid"], "dummy_token"),
    )
    monkeypatch.setattr(
        cloudflare_token_service,
        "delete_all_tokens",
        delete_all_tokens_mock,
    )
    monkeypatch.setattr(
        terraform_service, "terraform_apply", lambda x, y, z: (0, "success", None)
    )
    input_model = InputModel(
        environment="dev", fqdn="example.com.au", config_type="zone", action="apply"
    )
    # Test for main run - apply successful
    assert terraform_service.run(input_model, "working_directory") == "success"
    # Test for main run - plan successful
    input_model.action = "plan"
    assert terraform_service.run(input_model, "working_directory") == "success"

    # Test for main when plan with returncode other than 0
    monkeypatch.setattr(
        terraform_service, "terraform_plan", lambda x, y, z: (1, "Failed", None)
    )
    with pytest.raises(exceptions.TerraformServiceOperationException):
        terraform_service.run(input_model, "working_directory")

    # Test for main when init with returncode other than 0
    monkeypatch.setattr(
        terraform_service, "terraform_init", run_terraform_command_init_error_mock
    )
    with pytest.raises(exceptions.TerraformServiceOperationException):
        terraform_service.run(input_model, "working_directory")

    # Test for main when apply with returncode other than 0
    monkeypatch.setattr(
        terraform_service, "terraform_apply", lambda x, y, z: (1, "Failed", None)
    )
    with pytest.raises(exceptions.TerraformServiceOperationException):
        terraform_service.run(input_model, "working_directory")


def test_cf_terraforming_success(monkeypatch) -> None:
    monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(
        terraform_service, "terraform_init", lambda x, y, z: (0, "success", None)
    )
    monkeypatch.setattr(
        terraform_service, "terraform_init_reconfigure", lambda x, y, z: (0, "success", None)
    )
    monkeypatch.setattr(terraform_service, "create_providers_file", lambda x: None)
    monkeypatch.setattr(
        terraform_service, "run_terraform_command", run_terraform_command_import_mock
    )
    monkeypatch.setattr(
        cloudflare_token_service,
        "set_cloudflare_scoped_token",
        lambda x : (["tokenid"], "dummy_token"),
    )
    monkeypatch.setattr(
        cloudflare_token_service,
        "delete_all_tokens",
        delete_all_tokens_mock,
    )
    monkeypatch.setattr(helpers, "check_initial_token", check_initial_token_mock)

    # test single resource
    input_model = InputModel(
        environment="dev", fqdn="example.com.au", config_type="zone", action="plan"
    )
    output = terraform_service.cf_terraforming(
        input_model, "cloudflare_record"
    )
    assert "cloudflare_record" in output.keys()
    assert output["cloudflare_record"]["import_output"] == "terraform import x y/id1\nterraform import x y/id2"
    assert output["cloudflare_record"]["new_resources"] == []

    # test all resource
    input_model = InputModel(
        environment="dev", fqdn="example.com.au", config_type="zone", action="plan"
    )
    output = terraform_service.cf_terraforming(
        input_model, "all"
    )
    for resource in api_constant.CF_TERRAFORMING_RESOURCES:
        assert resource in output.keys()
        assert output[resource]["import_output"] == "terraform import x y/id1\nterraform import x y/id2"
        assert output[resource]["new_resources"] == []


# Mocks
def get_backend_key_mock(zone_name: str, config_type: str) -> str:
    return "backend_key"


def create_backend_file_mock(working_directory: str, state_key: str) -> None:
    return None

def run_terraform_command_mock(command: str, working_directory: str) -> tuple:
    return 0, "success", None


def run_terraform_command_init_error_mock(
    working_directory: str, zone: str, config_type: str
) -> tuple:
    return 1, "Failed", None

def run_terraform_command_import_mock(
    working_directory: str, name: str, token: str
) -> tuple:
    return 0, "terraform import x y/id1\nterraform import x y/id2", None

def copy_tf_files_mock(codebase_path: str, working_directory: str) -> tuple:
    return None


def create_api_token_mock(
    initial_token: str, token_name: str, policies: list, ttl: int
) -> str:
    return None

def delete_all_tokens_mock(initial_token: str, token_store: list) -> list:
    return ["123"]

def check_initial_token_mock(environment) -> str:
    return "api_token"


@pytest.fixture(autouse=True)
def run_around_tests():
    """
    Clean up the backend.tf file after each test.
    """
    yield
    if os.path.exists("backend.tf"):
        os.remove("backend.tf")
