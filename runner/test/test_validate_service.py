import pytest
import jsonschema
import yaml
from runner.src import validate_service
from runner.src import github_service
from runner.src.model import InputModel
from runner.src import exceptions
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src import helpers

input_model = InputModel(
    environment="dev", action="plan", config_type="zone", fqdn="zone_name"
)
jwt_token_info = JWTTokenInfo(
    repo_name="repo_name",
    branch_name="abc",
    authorized=True,
    org_name="CBA-General",
)


def test_main(monkeypatch):
    # Success case
    data_stream = yaml.dump({"zone_name": "zone_name"})
    monkeypatch.setattr(
        github_service,
        "get_download_url",
        lambda x, y, z: "download_url",
    )
    monkeypatch.setattr(
        helpers,
        "get_input_vars_path",
        lambda x, y, z: "input_vars_path",
    )
    monkeypatch.setattr(
        github_service,
        "get_file_content",
        lambda x, y: data_stream,
    )
    monkeypatch.setattr(
        jsonschema.Draft7Validator,
        "is_valid",
        lambda x, y: True,
    )
    assert validate_service.main(input_model, jwt_token_info) == {
        "config_type": "zone",
        "detail": "yaml is valid",
        "status": "success",
        "environment": "dev",
        "fqdn": "zone_name",
    }

    # Schema yaml Failure case - Not able to load schema yaml file
    input_model.config_type = "not_valid"
    with pytest.raises(exceptions.ValidateYAMLServiceException):
        validate_service.main(input_model, jwt_token_info)

    # Schema yaml Failure case - Not able to load schema yaml file
    input_model.config_type = "zone"
    monkeypatch.setattr(yaml, "safe_load", raise_yaml_load_error)
    with pytest.raises(exceptions.ValidateYAMLServiceException):
        validate_service.main(input_model, jwt_token_info)

    # Schema yaml Failure case - Generic exception
    input_model.config_type = "zone"
    monkeypatch.setattr(yaml, "safe_load", raise_generic_error)
    with pytest.raises(exceptions.ValidateYAMLServiceException):
        validate_service.main(input_model, jwt_token_info)

    # Input yaml Failure case - ValueError
    input_model.config_type = "zone"
    monkeypatch.setattr(yaml, "safe_load", yaml_load)
    monkeypatch.setattr(helpers, "get_input_vars_path", raise_value_error)
    with pytest.raises(exceptions.ValidateYAMLServiceException):
        validate_service.main(input_model, jwt_token_info)

    # Input yaml Failure case - YAMLError
    input_model.config_type = "zone"
    monkeypatch.setattr(
        helpers, "get_input_vars_path", lambda x, y, z: "input_vars_path"
    )
    monkeypatch.setattr(
        github_service,
        "get_file_content",
        lambda x, y: "invalid_yaml",
    )
    with pytest.raises(exceptions.ValidateYAMLServiceException):
        validate_service.main(input_model, jwt_token_info)

    # Input yaml Failure case - Generic exception
    monkeypatch.setattr(
        helpers, "get_input_vars_path", lambda x, y, z: "input_vars_path"
    )
    monkeypatch.setattr(
        github_service,
        "get_file_content",
        raise_generic_error,
    )
    with pytest.raises(exceptions.ValidateYAMLServiceException):
        validate_service.main(input_model, jwt_token_info)

    # Failure case - Validation error
    monkeypatch.setattr(
        github_service,
        "get_file_content",
        lambda x, y: data_stream,
    )
    class MockError:
        def __init__(self, message):
            self.message = message
            self.json_path = "$.zone_name"
            self.absolute_schema_path = "$.zone_name"
            self.path = "$.zone_name"
            self.validator = "type"
            self.validator_value = "string"
    errors = [MockError("ValidationError - Not a valid yaml file")]
    monkeypatch.setattr(jsonschema.Draft7Validator, "is_valid", lambda x, y: False)
    monkeypatch.setattr(jsonschema.Draft7Validator, "iter_errors", lambda x, y: [])

    with pytest.raises(exceptions.ValidateYAMLServiceException):
        validate_service.main(input_model, jwt_token_info)

    # Failure case - Generic exception
    monkeypatch.setattr(jsonschema.Draft7Validator, "is_valid", raise_generic_error)
    with pytest.raises(exceptions.ValidateYAMLServiceException):
        validate_service.main(input_model, jwt_token_info)


# Mock
def raise_yaml_validation_error(self, *args, **kwargs):
    raise jsonschema.ValidationError("ValidationError - Not a valid yaml file")


def raise_value_error(self, *args, **kwargs):
    raise ValueError("ValueError - Not a valid yaml file")


def raise_yaml_load_error(self, *args, **kwargs):
    raise yaml.YAMLError("YAMLError - Not a valid yaml file")


def raise_generic_error(self, *args, **kwargs):
    raise Exception("Generic error - Not a valid yaml file")


def yaml_load(file):
    if "invalid_yaml" in file:
        print("Invalid yaml file")
        raise yaml.YAMLError("YAMLError - Not a valid yaml file")
    return {}
