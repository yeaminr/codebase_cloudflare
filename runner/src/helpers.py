"""
Helper functions
"""
import os
import datetime
import logging
import yaml
import requests
from cloudflare import Cloudflare
from cloudflare.types.user import TokenCreateResponse
from runner.src import api_constant
from runner.src import exceptions
from runner.src import hashicorp_vault_service

logger = logging.getLogger(__name__)


def create_api_token(initial_token: str, token_name: str,
                     policies: list, ttl: int = 15) -> TokenCreateResponse:
    """
    Create a Cloudflare API token with the provided policies and TTL

    Parameters:
    initial_token: str: initial token with permissions to create additional tokens
    policies: list = [{
        "effect": "allow" | "deny",
        "permission_groups": [
            {
                "id": permission["id"],
                "name": permission["name"]
            }
        ],
        "resources": {
            # only read zones within provided account
            f"com.cloudflare.api.account.{account_id}": "*"
        }
    }]
    ttl: int: time to live for the token in minutes. Default to 15 minutes
    """
    logger.info("Creating API token with policies: %s", policies)
    create_token_client = Cloudflare(api_token=initial_token)
    ttl_obj = datetime.datetime.now() + datetime.timedelta(minutes=ttl)
    token = create_token_client.user.tokens.create(
        name=token_name, policies=policies, expires_on=ttl_obj.strftime("%Y-%m-%dT%H:%M:%SZ"))
    if not token:
        logger.info("API returned None... Failed to create a token with provided policy...")
        raise ValueError(
            "API returned None... Failed to create a token with provided policy...")
    if not token.value:
        logger.info("Token value is None... Failed to create a token with provided policy...")
        raise ValueError(
            "Token value is None... Failed to create a token with provided policy...")
    return token


def delete_api_token(initial_token: str, token_id: str):
    """
    Delete the token with the provided token ID

    Parameters:
    initial_token: str: initial token with permissions to create additional tokens
    token_id: str: token ID to delete
    """
    logger.info("Deleting API token with token ID: %s", token_id)
    create_token_client = Cloudflare(api_token=initial_token)
    delete_token = create_token_client.user.tokens.delete(token_id)
    if not delete_token:
        logger.info("API returned None... Failed to delete the token with the provided token ID...")
        raise ValueError(
            "API returned None... Failed to delete the token with the provided token ID...")


def get_permission_groups(initial_token: str, permissions: list[dict]) -> list:
    """
    Get the permission groups for the provided permission names. E.g. Zone Read

    Parameters:
    initial_token: str: initial token with permissions to create additional tokens
    permissions: list[dict]: list of objects with permission name and scope

    Returns:
    list: permission groups for the provided permission names. [{id, name}]

    Raises:
    ValueError: if the permission group for the provided permission name is not found
    """
    logger.info("Call get_permission_groups")
    create_token_client = Cloudflare(api_token=initial_token)
    permission_groups = create_token_client.user.tokens.permission_groups.list()

    permission_ids = []
    for permission in permissions:
        scope = permission.get("scope", "").lower()
        if scope == "account":
            req_scope = "com.cloudflare.api.account"
        elif scope == "zone":
            req_scope = "com.cloudflare.api.account.zone"
        else:
            raise ValueError(
                f"Invalid scope {permission['scope']}. Please provide a valid scope.")

        permission_group = next(
            (permission_group for permission_group in permission_groups
             if permission_group["name"] == permission['name'] and req_scope in permission_group["scopes"]), {})
        if not permission_group:
            logger.info(
                "Could not find the permission group for the provided permission name %s with scope %s",
                permission['name'], scope)
            raise ValueError(
                f"Could not find the permission group for the provided permission name {permission} with scope {scope}")
        permission_ids.append(
            {"id": permission_group["id"], "name": permission_group["name"]})

    return permission_ids


def validate_yaml_file(yaml_file: str, required_keys: list) -> dict:
    """
    Validate that the provided path to the tenant input file is valid
    Check file exists and has all the required parameters
    Return contents of the file

    Parameters:
    yaml_file: str: path to the tenant input file
    required_keys: list: list of required keys in the tenant input file

    Returns:
    dict: contents of the tenant input file

    Errors:
    FileNotFoundError: if the file does not exist
    ValueError: if the file does not have all the required parameters
    """
    if not os.path.exists(yaml_file):
        raise FileNotFoundError(
            f"File {yaml_file} does not exist! Please provide a valid file path.")

    with open(yaml_file, "r") as file:
        tenant_input = yaml.safe_load(file)

    if not tenant_input:
        raise ValueError(
            f"File {yaml_file} is empty! "
            f"Please provide a valid file with the required parameters: {required_keys}")

    # find all missing keys
    errors = []
    for key in required_keys:
        if key not in tenant_input:
            errors.append(key)

    if errors:
        raise ValueError(
            "The following required parameters are missing from "
            f"the tenant input YAML file: {errors}")

    return tenant_input


def get_zone_id(zone_name: str, zone_read_token: str) -> str:
    """
    get zone ID for the provided zone name
    Parameters:
    zone_name: str: zone name
    zone_read_token: str: token that has permission to read zones within provided account

    Returns:
    str: zone ID
    """
    zone_read_client = Cloudflare(api_token=zone_read_token)
    zones = zone_read_client.zones.list()
    if not zones:
        raise ValueError(
            "API returned None... Failed to get the list of zones")
    if not zones.result:
        raise ValueError("No zones found in the account...")
    zone_id = next((zone.id for zone in zones if zone.name == zone_name), "")
    if not zone_id:
        raise ValueError(
            f"Failed to find the zone ID for the zone name {zone_name}. "
            "Please ensure provided zone name is correct.")
    return zone_id


def get_operation_from_codebase_path(codebase_path: str):
    """
    DHP runner API expects a path to the terraform code to be provided
    as part of the payload. Different paths are used for different operations.
    Extracts the operation from the codebase path
    Operations include account, cdn, security, tls, mtls

    Args
    ----
    codebase_path (str): The path to the codebase. e.g. cf/terraform/cdn
    """
    return codebase_path.split("/")[-1]


def get_account_id(env: str, accounts_file_path: str):
    """
    Read the account YAML file and get the account id from the env provided

    Args
    ----
    env (str): dev, test, stg, prod
    """
    with open(accounts_file_path, "r") as file:
        accounts = yaml.safe_load(file)
        return accounts[env]


def get_zone_name_from_yaml(cwd):
    """
    Get the zone name (FQDN) from the yaml file.

    Returns:
        str: The hosted zone name.

    Raises:
        KeyError: If zone_name not in yaml file.
    """
    zone_yaml_file_path = f"{cwd}/zone_parameters.yml"
    if os.path.isfile(zone_yaml_file_path):
        with open(zone_yaml_file_path, "r") as file:
            config = yaml.safe_load(file)
            if "zone_name" in config:
                return config["zone_name"]
            raise KeyError("zone_name key not in zone_parameters.yml")
    raise FileNotFoundError(f"Zone file not found: {zone_yaml_file_path}")


def get_parameters_yaml(cwd: str, config_type: str) -> dict:
    """
    Get the parameters from the yaml file in current working directory for the provided config type.
    Returns:
        str: The parameters from the yaml file.

    Raises:
        ValueError: If cwd or config_type is not provided.
        FileNotFoundError: If the yaml file for the config type is not found.
    """
    if not cwd or not config_type:
        raise ValueError("cwd and config_type must be provided")
    file_path = f"{cwd}/{config_type}_parameters.yml"
    if os.path.isfile(file_path):
        with open(file_path, "r", encoding="utf-8") as file:
            config = yaml.safe_load(file)
            return config
    raise FileNotFoundError(f"{config_type} file not found in the path: {file_path}")

def get_input_vars_path(environment: str, zone: str, config_type: str) -> str:
    """
    Get the path to the input vars file for the provided environment, zone and config type

    Args
    ----
    environment (str): The environment to deploy to. e.g. dev, test, prod
    zone (str): The zone to deploy to. e.g. example.com
    config_type (str): The type of config. e.g. account, zone, cdn, security, tls, mtls, workers

    Returns
    -------
    str: The path to the input vars file
    """
    config_type = config_type.lower()
    environment = environment.lower()
    if config_type == "account":
        return f"{environment}/account_parameters.yml"
    elif config_type == "zone":
        return f"{environment}/{zone}/zone_parameters.yml"
    elif config_type in ["cdn", "security", "tls", "cert", "mtls", "workers", "app_list"]:
        return f"{environment}/{zone}/{config_type}/{config_type}_parameters.yml"
    raise ValueError("Invalid config type: "
                     f"{config_type}. Please provide a valid config type.")


def check_initial_token(environment: str) -> str:
    """
    Check if the Initial API Token value set in the environment variable is active.
    If it's not active then this function fetches the active Initial API Token from the Vault.

    Parameters:
    environment (str): Environment or Cloudflare Account

    Returns:
    The Active Initial API Token
    """

    current_initial_token = api_constant.cf_initial_api_token
    if current_initial_token is None:
        logger.info("cf_initial_api_token is not set")
        raise exceptions.TokenServiceMissingInitialApiTokenException()

    verify_request_headers = {
        "Authorization": f"Bearer {current_initial_token}"
        }

    try:
        # Ref: https://developers.cloudflare.com/api/resources/user/subresources/tokens/methods/verify/
        verify_token_response = requests.get(api_constant.cf_token_verify_url, headers=verify_request_headers, verify=True)
        response_status_code = verify_token_response.status_code
        logger.info("verify_token_response.status_code =============>>>> %s", response_status_code)

        token_valid = False
        if response_status_code == 200:
            verify_token_response_json = verify_token_response.json()
            logger.info("verify_token_response.json() =============>>>> %s", verify_token_response_json)
            token_status = verify_token_response_json['result']['status']
            if token_status == "active":
                token_valid = True
            elif token_status in ("disabled", "expired"):
                logger.info("~~~~~~~~~~~~~~~ TOKEN STATUS IS NOT ACTIVE ~~~~~~~~~~~~ token_status >> %s", token_status)
                token_valid = False
        elif response_status_code == 401:
            logger.info("~~~~~~~~~~~~~~~ RESPONSE STATUS CODE IS NOT 200 ~~~~~~~~ response_status_code >>> %s", response_status_code)
            token_valid = False

        if token_valid:
            logger.info("Initial Token is valid and active")
            return current_initial_token

        # Getting vault_token to access Hashicorp vault
        vault_token = hashicorp_vault_service.get_vault_token()
        if not vault_token:
            raise exceptions.TokenServiceException("Failed to get vault token")
        logger.info("--- Secured Vault Token successfully ---")

        # Set Vault URL, namespace and secret path
        vault_url = api_constant.VAULT_URL
        vault_namespace = api_constant.VAULT_NAMESPACE_CYBER_DHP
        vault_secret_path = api_constant.vault_secret_path_map_dhp[environment]
        full_url = vault_url+"/v1/"+vault_namespace+"/kv/data/"+vault_secret_path
        logger.info("full_url ----------> %s", full_url)

        new_initial_token = hashicorp_vault_service.read_secret_from_vault(
            full_url,
            vault_token,
            "env.CLOUDFLARE_INITIAL_API_TOKEN"
            )
        if not new_initial_token:
            raise exceptions.TokenServiceException("Failed to update in Vault")

        new_initial_token_id = hashicorp_vault_service.read_secret_from_vault(
            full_url,
            vault_token,
            "env.CLOUDFLARE_INITIAL_API_TOKEN_ID"
            )
        if not new_initial_token_id:
            raise exceptions.TokenServiceException("Failed to update in Vault")

        os.environ["CLOUDFLARE_INITIAL_API_TOKEN"] = new_initial_token
        os.environ["CLOUDFLARE_INITIAL_API_TOKEN_ID"] = new_initial_token_id
        return new_initial_token

    except Exception as e:
        logger.error ("Error verifying CF API Token: %s", e)
        raise exceptions.TokenServiceException("Error verifying API Token.")
