"""
Module to create and manage Cloudflare API tokens with specific permissions.
"""
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
from runner.src import helpers
from runner.src import hashicorp_vault_service

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
    logger.info("Creating read zone token")
    permission_names = [{"name": "Zone Read", "scope": "zone"}]
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
        create_token, "Runner: Read Zone Token", policies, ttl
    )
    token_value = zone_read_token.value
    token_id = zone_read_token.id
    token_store.append(token_id)
    return token_value, token_store


def segregate_permission_lists(token_permission_list: list) -> tuple[list, list]:
    """
    Segregate the permission list into zone and account permissions

    Parameters:
    token_permission_list: list: list of permissions

    Returns:
    list: zone_permission_list: list of zone permissions
    list: account_permission_list: list of account permissions
    """
    logger.info("Segregating permission lists")
    zone_permission_list = []
    account_permission_list = []
    for permission in token_permission_list:
        if permission['scope'] == 'zone':
            zone_permission_list.append(permission)
        elif permission['scope'] == 'account':
            account_permission_list.append(permission)

    return zone_permission_list, account_permission_list


def create_zone_level_scoped_token(
    cf_initial_api_token: str, token_permissions: list, zone_id: str, token_store: list, token_name: str
) -> tuple[str, list]:
    """
    Create a zone level scoped token based on the permissions and the initial API token
    """
    logger.info("Creating zone level scoped token with name %s for zone %s", token_name, zone_id)
    permission_groups = helpers.get_permission_groups(
        cf_initial_api_token, token_permissions
    )

    policies = [
        {
            "effect": "allow",
            "permission_groups": permission_groups,
            "resources": {
                # only be able to do things within provided zone
                f"com.cloudflare.api.account.zone.{zone_id}": "*"
            },
        }
    ]
    ttl = api_constant.cf_token_ttl_minutes
    token = helpers.create_api_token(
        cf_initial_api_token,
        token_name,
        policies,
        ttl,
    )

    token_value = token.value
    token_id = token.id
    token_store.append(token_id)
    logger.info("Returning token store: %s", token_store)
    return token_value, token_store


def create_mixed_level_scoped_token(
        cf_initial_api_token: str, token_permissions: list, account_id: str,
        zone_id: str, token_store: list, token_name: str) -> tuple[str, list]:
    """
    Create zone and account level scoped token based on permissions and the initial API token
    """
    logger.info("Creating mixed level scoped token with name %s for zone %s and account %s", token_name, zone_id, account_id)
    zone_permission_list, account_permission_list = segregate_permission_lists(
        token_permissions)

    zone_permission_groups = helpers.get_permission_groups(
        cf_initial_api_token, zone_permission_list
    )
    account_permission_groups = helpers.get_permission_groups(
        cf_initial_api_token, account_permission_list
    )

    policies = [
        {
            "effect": "allow",
            "permission_groups": account_permission_groups,
            "resources": {
                f"com.cloudflare.api.account.{account_id}": "*"
            }
        },
        {
            "effect": "allow",
            "permission_groups": zone_permission_groups,
            "resources": {
                f"com.cloudflare.api.account.zone.{zone_id}": "*"
            }
        }
    ]
    ttl = api_constant.cf_token_ttl_minutes
    token = helpers.create_api_token(
        cf_initial_api_token,
        token_name,
        policies,
        ttl,
    )

    token_value = token.value
    token_id = token.id
    token_store.append(token_id)
    logger.info("Returning token store: %s", token_store)
    return token_value, token_store


def create_account_level_scoped_token(
    cf_initial_api_token: str, token_permissions: list, account_id: str, token_store: list, token_name: str
) -> tuple[str, list]:
    """
    Create an account level scoped token based on the permissions and the initial API token

    Parameters:
    cf_initial_api_token: str: token created in Cloudflare using the Create Additional Tokens template
    token_permissions: list: list of permissions to be added to the token
    account_id: str: account ID
    token_store: list: list of currently active tokens to store the token ID
    token_name: str: name of the token
    """
    logger.info("Creating account level scoped token with name %s for account %s", token_name, account_id)
    permission_groups = helpers.get_permission_groups(
        cf_initial_api_token, token_permissions
    )

    policies = [
        {
            "effect": "allow",
            "permission_groups": permission_groups,
            "resources": {
                # only be able to do things within provided account
                f"com.cloudflare.api.account.{account_id}": "*"
            },
        }
    ]
    ttl = api_constant.cf_token_ttl_minutes
    token = helpers.create_api_token(
        cf_initial_api_token,
        token_name,
        policies,
        ttl,
    )
    token_value = token.value
    token_id = token.id
    token_store.append(token_id)
    logger.info("Returning token store: %s", token_store)
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
    logger.info("Deleting all tokens in the token store: %s", token_store)
    deleted_tokens = []
    for token_id in token_store:
        try:
            helpers.delete_api_token(initial_token, token_id)
            deleted_tokens.append(token_id)
        except (BadRequestError, ValueError) as e:
            logger.error(
                "Failed to delete token with token ID %s. Error: %s", token_id, e)
    return deleted_tokens


def set_cloudflare_scoped_token(input_model: InputModel) -> tuple[list, str]:
    """
    check that the initial Cloudflare API token is set and create the scoped token
    with the required permission for the config_type/operation

    Args:
    -----
    input_model (InputModel): input model
    """
    logger.info("Setting Cloudflare scoped token")
    cf_initial_api_token = helpers.check_initial_token(input_model.environment)
    if cf_initial_api_token is None:
        logger.info("Initial API token is not set")
        raise exceptions.TokenServiceMissingInitialApiTokenException()

    # get the required permissions scopes required for this operation
    if input_model.action == "apply":
        logger.info("Performing write operation")
        token_permissions = operation_permissions_map[input_model.config_type]["write"]
    else:
        logger.info("Performing read operation")
        token_permissions = operation_permissions_map[input_model.config_type]["read"]
    logger.info(
            "Creating API token with permissions: %s", token_permissions
        )

    # get name of token
    token_name = get_token_name(input_model)
    logger.info("Creating token with name: %s", token_name)

    # get the level of the operation. Can be either account or zone
    token_level = operation_level_map[input_model.config_type]
    token_store = []
    if token_level.lower() == "account":
        logger.info("Perform account level operation")
        scoped_api_token, token_store = create_account_level_scoped_token(
            cf_initial_api_token, token_permissions, input_model.account_id, token_store, token_name
        )
    elif token_level.lower() == "mixed":
        logger.info("Perform mixed level operation")
        read_zone_token, token_store = create_read_zone_token(
            cf_initial_api_token, input_model.account_id, token_store)
        if not input_model.fqdn:
            raise exceptions.TokenServiceMissingZoneNameException(
                "Missing zone name for zone level operation")
        zone_id = helpers.get_zone_id(input_model.fqdn, read_zone_token)
        logger.info("Zone ID: %s", zone_id)
        logger.info(
            "Creating mixed level API token with permissions: %s", token_permissions
        )
        scoped_api_token, token_store = create_mixed_level_scoped_token(
            cf_initial_api_token, token_permissions, input_model.account_id, zone_id, token_store, token_name
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
            cf_initial_api_token, token_permissions, zone_id, token_store, token_name
        )
    logger.info("Token store: %s", token_store)
    return token_store, scoped_api_token


def delete_cloudflare_scoped_token(token_id: str, environment: str):
    """
    Deletes the created cloudflare scoped token

    Args:
        token_id: str: ID of the token to be deleted
    """
    cf_initial_api_token = helpers.check_initial_token(environment)
    if cf_initial_api_token is None:
        raise exceptions.TokenServiceMissingInitialApiTokenException()

    try:
        helpers.delete_api_token(cf_initial_api_token, token_id)
    except (BadRequestError, ValueError) as e:
        logger.error(
            "Failed to delete token with token ID %s. Error: %s", token_id, e)
        raise


def get_token_name(input_model: InputModel) -> str:
    """
    Return name of token based on input model
    """
    if input_model.fqdn:
        return f"Runner: {input_model.environment} {input_model.config_type} {input_model.action} {input_model.fqdn}"
    return f"Runner: {input_model.environment} {input_model.config_type} {input_model.action}"


def rotate_cloudflare_initial_token(environment: str) -> bool:
    """
    Rotate the Cloudflare initial token

    Parameters:
        environment (str): environment to rotate the token for
    Returns:
        vault_update_response (bool): True if the token is rotated successfully, False otherwise
    """

    logger.info("Rotating initial token for env %s ...", environment)
    try:
        # Getting the old Initial Token ID
        old_initial_token_id = api_constant.cf_initial_api_token_id
        if old_initial_token_id is None:
            logger.info("cf_initial_api_token is not set")
            raise exceptions.TokenServiceMissingInitialApiTokenException()
        logger.info("Old initial token ID: -------------->>> %s", old_initial_token_id)

        # Getting old initial token value
        old_initial_token = api_constant.cf_initial_api_token
        if old_initial_token is None:
            logger.info("cf_initial_api_token is not set")
            raise exceptions.TokenServiceMissingInitialApiTokenException()
        logger.info("Old initial token: -------------->>> %s", old_initial_token)

        # Setting the policy for the new Initial Token
        policies = [
            {
                "effect": "allow",
                "permission_groups": [api_constant.cf_perm_grp_api_tokens_write],
            }
        ]

        return False

        # Creating new Initial API Token in Cloudflare
        logger.info("Creating a new initial token for >>>>  %s", environment)
        new_initial_token = helpers.create_api_token(
            old_initial_token,
            "Runner: Initial Token",
            policies,
            api_constant.cf_initial_token_validity
            )
        logger.info("New initial token created successfully")
        #logger.info("new_initial_token -=-=-=-=-=-=-=-=>>> %s", new_initial_token)

        # Getting vault_token to access Hashicorp vault
        vault_token = hashicorp_vault_service.get_vault_token()
        if not vault_token:
            raise exceptions.TokenServiceException("Failed to get vault token")
        logger.info("--- Secured Vault Token successfully ---")
        logger.info("vault_token -----------------> %s", vault_token)

        # Set Vault URL, namespace and secret path
        vault_url = api_constant.VAULT_URL
        vault_namespace = api_constant.VAULT_NAMESPACE_CYBER_DHP
        vault_secret_path = api_constant.vault_secret_path_map_dhp[environment]
        full_url = vault_url+"/v1/"+vault_namespace+"/kv/data/"+vault_secret_path
        logger.info("full_url ----------> %s", full_url)

        # Update initial token in Hashicorp Vault
        update_cf_token_response = hashicorp_vault_service.update_secret_in_vault(
            full_url,
            vault_token,
            "env.CLOUDFLARE_INITIAL_API_TOKEN",
            new_initial_token.value
            )
        if not update_cf_token_response:
            raise exceptions.TokenServiceException("Failed to update in Vault")
        logger.info("--- Updated Initial Token value successfully ---")

        # Update initial token id in Hashicorp Vault
        update_cf_token_id_response = hashicorp_vault_service.update_secret_in_vault(
            full_url,
            vault_token,
            "env.CLOUDFLARE_INITIAL_API_TOKEN_ID",
            new_initial_token.id)
        if not update_cf_token_id_response:
            raise exceptions.TokenServiceException("Failed to update in Vault")
        logger.info("--- Updated Initial Token ID successfully ---")

        # Delete the old initial token
        helpers.delete_api_token(new_initial_token.value, old_initial_token_id)
        logger.info("Old initial token deleted successfully")

        return True
    except Exception as e:
        logger.error("Failed to rotate API token: %s", e)
        raise exceptions.TokenServiceException("Failed to rotate API token")
