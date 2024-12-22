import os
import logging
from cloudflare import BadRequestError
from runner.src import api_constant
from runner.src import exceptions
from runner.src.model import InputModel
from runner.src.cloudflare_permission_mapper import (
    operation_permissions_map,
    operation_level_map,
)
from cf.python.src import helpers

logger = logging.getLogger(__name__)

def create_read_zone_token(create_token: str, account_id: str,
                           token_store: list) -> tuple[str, list]:
    """
    create a token with read zone permissions
    Parameters:
    create_token: str: token created in Cloudflare using the Create Additional Tokens template
    account_id: str: account ID
    token_store: list: list of currently active tokens to store the token ID

    Returns:
    tuple[str, list]: token that has permission to read zones within provided account, 
                      list of currently active tokens
    """
    permission_names = ["Zone Read"]
    permission_groups = helpers.get_permission_groups(
        create_token, permission_names)
    policies = [
        {
            "effect": "allow",
            "permission_groups": permission_groups,
            "resources": {
                # only read zones within provided account
                f"com.cloudflare.api.account.{account_id}": "*"
            },
        }
    ]

    ttl = api_constant.cf_token_ttl_minutes
    zone_read_token = helpers.create_api_token(
        create_token, "Terraform Service: Read Zone Token", policies, ttl
    )
    token_value = zone_read_token.value
    token_id = zone_read_token.id
    token_store.append(token_id)
    return token_value, token_store


def create_zone_level_scoped_token(
    cf_initial_api_token: str, token_permissions: list, zone_id: str, token_store: list
) -> tuple[str, list]:
    """
    Create a zone level scoped token based on the permissions and the initial API token
    """
    permission_groups = helpers.get_permission_groups(
        cf_initial_api_token, token_permissions
    )

    policies = [
        {
            "effect": "allow",
            "permission_groups": permission_groups,
            "resources": {
                # only be able to write SSL and Certificates settings within provided zone
                f"com.cloudflare.api.account.zone.{zone_id}": "*"
            },
        }
    ]
    ttl = api_constant.cf_token_ttl_minutes
    token = helpers.create_api_token(
        cf_initial_api_token,
        "Terraform Service: Zone Level Scoped Token",
        policies,
        ttl,
    )

    token_value = token.value
    token_id = token.id
    token_store.append(token_id)
    return token_value, token_store


def create_account_level_scoped_token(
    cf_initial_api_token: str, token_permissions: list, account_id: str, token_store: list
) -> tuple[str, list]:
    """
    Create an account level scoped token based on the permissions and the initial API token
    """
    permission_groups = helpers.get_permission_groups(
        cf_initial_api_token, token_permissions
    )

    policies = [
        {
            "effect": "allow",
            "permission_groups": permission_groups,
            "resources": {
                # only be able to write SSL and Certificates settings within provided zone
                f"com.cloudflare.api.account.{account_id}": "*"
            },
        }
    ]
    ttl = api_constant.cf_token_ttl_minutes
    token = helpers.create_api_token(
        cf_initial_api_token,
        "Terraform Service: Account Level Scoped Token",
        policies,
        ttl,
    )
    token_value = token.value
    token_id = token.id
    token_store.append(token_id)
    return token_value, token_store


def delete_all_tokens(initial_token: str, token_store: list) -> list:
    """
    Delete all the tokens in the token store

    Parameters:
    initial_token: str: initial token with permissions to create additional tokens
    token_store: list: list of currently active token id's

    Returns:
    list: list of deleted token id's
    """
    deleted_tokens = []
    for token_id in token_store:
        try:
            helpers.delete_api_token(initial_token, token_id)
            deleted_tokens.append(token_id)
        except BadRequestError as e:
            logger.error(
                "Failed to delete token with token ID %s. Error: %s", token_id, e)
        except ValueError as e:
            logger.error(
                "Failed to delete token with token ID %s. Error: %s", token_id, e)
    return deleted_tokens


def set_cloudflare_scoped_token(input_model: InputModel) -> list:
    """
    check that the initial Cloudflare API token is set and create the scoped token
    with the required permission for the config_type/operation

    Args:
    -----
    input_model (InputModel): input model
    """
    cf_initial_api_token = api_constant.cf_initial_api_token
    if cf_initial_api_token is None:
        raise exceptions.TokenServiceMissingInitialApiTokenException()
    
    # get the required permissions scopes required for this operation
    if input_model.action == "apply":
        token_permissions = operation_permissions_map[input_model.config_type]["write"]
    else:
        token_permissions = operation_permissions_map[input_model.config_type]["read"]
    # get the level of the operation. Can be either account or zone
    token_level = operation_level_map[input_model.config_type]  # account or zone
    token_store = []
    if token_level.lower() == "account":
        logger.info("Perform account level operation")
        logger.info(
            "Creating account level API token with permissions: %s", token_permissions
        )
        scoped_api_token, token_store = create_account_level_scoped_token(
            cf_initial_api_token, token_permissions, input_model.account_id, token_store
        )
    else:
        logger.info("Perform zone level operation")
        read_zone_token, token_store = create_read_zone_token(
            cf_initial_api_token, input_model.account_id, token_store)
        if not input_model.fqdn:
            raise exceptions.TokenServiceMissingZoneNameException(
                "Missing zone name for zone level operation")
        zone_id = helpers.get_zone_id(input_model.fqdn, read_zone_token)
        logger.info("Zone ID: %s", zone_id)
        logger.info(
            "Creating zone level API token with permissions: %s", token_permissions
        )
        scoped_api_token, token_store = create_zone_level_scoped_token(
            cf_initial_api_token, token_permissions, zone_id, token_store
        )
    os.environ["CLOUDFLARE_API_TOKEN"] = scoped_api_token
    return token_store
