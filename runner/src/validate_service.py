import logging
import yaml
import jsonschema
from runner.src import github_service
from runner.src.model import InputModel
from runner.src import exceptions
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src import helpers

logger = logging.getLogger(__name__)


def main(input_model: InputModel, jwt_token_info: JWTTokenInfo) -> dict:
    """
    Main function to run the YAML service validation

    Parameters:
    input_model: InputModel: Input model object
    jwt_token_info: JWTTokenInfo: JWT token info object

    Returns:
    dict: Dictionary with status and message

    Raises:
    ValidateYAMLServiceException: If there is an error in yaml service main
    """
    try:
        schema_yaml = get_schema_yaml(input_model.config_type)
        input_data = get_input_yaml(input_model, jwt_token_info)
        validate_yaml(input_data, schema_yaml)
        return {
            "status": "success",
            "detail": "yaml is valid",
            "config_type": input_model.config_type,
            "environment": input_model.environment,
            "fqdn": input_model.fqdn,
        }
    except Exception as e:
        logger.error("Unexpected error in yaml service main")
        raise exceptions.ValidateYAMLServiceException(
            f"Error in yaml service main: {str(e)}"
        )


def get_input_yaml(input_model: InputModel, jwt_token_info: JWTTokenInfo) -> dict:
    """
    Get the input yaml from Github

    Parameters:
    input_model: InputModel: Input model object
    jwt_token_info: JWTTokenInfo: JWT token info object

    Returns:
    dict: Input yaml data

    Raises:
    ValidateYAMLServiceException: If there is an error in getting input yaml
    """
    try:
        input_vars_path = helpers.get_input_vars_path(
            input_model.environment, input_model.fqdn, input_model.config_type
        )
        input_url = github_service.get_download_url(
            jwt_token_info.repo_name, input_vars_path, jwt_token_info.branch_name
        )
        input_data = github_service.get_file_content(input_url, None)
        return yaml.safe_load(input_data)
    except ValueError as e:
        logger.error("Input yaml ValueError: %s", e)
        raise exceptions.ValidateYAMLServiceException("Error in getting input yaml")
    except yaml.YAMLError as e:
        logger.error("Input yaml YAMLError: %s", e)
        raise exceptions.ValidateYAMLServiceException(
            f"Input yaml file YAMLError for config_type : {input_model.config_type}"
        )
    except Exception as e:
        logger.exception("Unexpected error in get_input_yaml")
        raise exceptions.ValidateYAMLServiceException(
            f"Error in get_input_yaml: {str(e)}"
        )


def get_schema_yaml(config_type: str) -> dict:
    """
    Get the schema data from schema folder

    Parameters:
    config_type: str: The type of config. e.g. account, zone, cdn, security, tls, mtls, workers

    Returns:
    dict: Schema data

    Raises:
    ValidateYAMLServiceException: If there is an error in getting schema data
    """
    try:
        with open(
            f"schema/{config_type}_parameters_schema.yml", "r", encoding="utf-8"
        ) as schema:
            return yaml.safe_load(schema)
    except FileNotFoundError as e:
        logger.error("Schema FileNotFoundError: %s", e)
        raise exceptions.ValidateYAMLServiceException(
            f"Schema file not found for {config_type}"
        )
    except yaml.YAMLError as e:
        logger.error("Schema file YAMLError : %s", e)
        raise exceptions.ValidateYAMLServiceException(
            f"Schema file YAMLError for config_type : {config_type}"
        )
    except Exception as e:
        logger.exception("Unexpected error in get_schema_yaml")
        raise exceptions.ValidateYAMLServiceException(
            f"Error in get_schema_yaml: {str(e)}"
        )


def validate_yaml(input_yaml: dict, schema_yaml: dict) -> None:
    """
    Validate the input yaml against the schema

    Parameters:
    input_yaml: dict: Input yaml data
    schema_yaml: dict: Schema data

    Raises:
    ValidateYAMLServiceException: If there is an error in yaml validation
    """
    try:
        validator = jsonschema.Draft7Validator(schema_yaml)
        response = []
        if not validator.is_valid(input_yaml):
            errors = validator.iter_errors(input_yaml)
            for error in errors:
                response.append({"error": error.message, "path": error.json_path})
            raise exceptions.ValidateYAMLServiceException(str(response))
    except Exception as e:
        logger.exception("Unexpected error in validate_yaml")
        raise exceptions.ValidateYAMLServiceException(f"Error validate_yaml: {str(e)}")
