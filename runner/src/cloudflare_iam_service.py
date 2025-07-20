"""
Service for Cloudflare IAM related operations
"""
import logging
import yaml

from cloudflare import Cloudflare

from runner.src import exceptions
from runner.src import api_constant
from runner.src import cloudflare_token_service
from runner.src import helpers

logger = logging.getLogger(__name__)


def get_domain_group(account_id: str, resource_group_id: str, scoped_api_token: str) -> list:
    """
    Get the resource group details for the given account ID and Resource Group ID.

    Args:
        account_id (str): The account ID to get the resource group for.
        resource_group_id (str): The resource group ID to get.
        scoped_api_token (str): The API token to be used to get Resource Group details.
    Returns:
        list: The resource group scope objects for the given account ID.

    Raises:
        exceptions.CloudflareIAMException: If the request to get the resource group fails.
    """

    cf_client = Cloudflare(api_token=scoped_api_token)
    try:
        resource_group_get_response = cf_client.iam.resource_groups.get(account_id=account_id, 
                                        resource_group_id=resource_group_id)
        resource_groups_scope = resource_group_get_response.result['scope']
        resource_groups_scope_objects = resource_groups_scope['objects']
        return resource_groups_scope_objects
    except Exception as e:
        logger.error("Failed to get resource group for account ID %s: %s", account_id, e)
        raise exceptions.CloudflareIAMServiceException("Failed to get resource group")


def update_domain_group(account_id: str, resource_group_id: str, zone_id: str, scoped_api_token: str) -> list:
    """
    Update the resource group details for the given account ID and Resource Group ID.

    Args:
        account_id (str): The account ID to get the resource group for.
        resource_group_id (str): The resource group ID to get.
        zone_id (str): The zone ID to be added to the domain group.
        scoped_api_token (str): The API token to be used to update Resource Group.
    Returns:
        list: The resource group scope objects for the given account ID.

    Raises:
        exceptions.CloudflareIAMException: If the request to update the resource group fails.
    """

    current_resource_groups_scope_objects = get_domain_group(account_id, resource_group_id, scoped_api_token)
    logger.info("Returend by get_domain_group() Current Resource Group Scope Objects >>> : %s", current_resource_groups_scope_objects)

    for obj in current_resource_groups_scope_objects:
        if obj['key'] == f'com.cloudflare.api.account.zone.{zone_id}':
            logger.info("Zone ID %s already exists in the Resource Group: %s", zone_id, resource_group_id)
            return current_resource_groups_scope_objects

    current_resource_groups_scope_objects.append({'key': f'com.cloudflare.api.account.zone.{zone_id}'})
    logger.info("Current Resource Groups Scope Objects after append : %s", current_resource_groups_scope_objects)

    resource_group_scope = {
        "key": f"com.cloudflare.api.account.{account_id}",
        "objects": current_resource_groups_scope_objects
    }
    logger.info("Updated Resource Group Scope: %s", resource_group_scope)

    cf_client = Cloudflare(api_token=scoped_api_token)
    try:
        # Update the current resource group details
        resource_group_update_response = cf_client.iam.resource_groups.update(account_id=account_id,
                                        resource_group_id=resource_group_id, scope=resource_group_scope)
        logger.info("Resource Group Update Response: %s ", resource_group_update_response)
        return current_resource_groups_scope_objects
    except Exception as e:
        logger.error("Failed to update resource group for account ID %s: %s", account_id, e)
        raise exceptions.CloudflareIAMServiceException("Failed to update resource group")


def add_zone_to_domain_group(environment: str, fqdn: str) -> list:
    """
    Add a zone to the domain group.

    Args:
        environment (str): The environment for which the zone ID to be added to the domain group.
        fqdn (str): The fqdn for which the zone ID to be added to the domain group.
    Returns:
        list: The updated resource group response.

    Raises:
        exceptions.CloudflareIAMException: If the request to add the zone to domain group fails.
    """

    with open(api_constant.ACCOUNTS_FILE_PATH, "r") as account_yml:
        account_yml_content = yaml.safe_load(account_yml)
    with open(api_constant.DOMAIN_GROUPS_FILE_PATH, "r") as domain_groups_yml:
        domain_groups_yml_content = yaml.safe_load(domain_groups_yml)

    account_id = account_yml_content[environment]
    domain_group_id = domain_groups_yml_content[environment]
    logger.info("Account ID and Domain Group Id: %s %s", account_id, domain_group_id)

    cf_initial_api_token = helpers.check_initial_token(environment)
    if cf_initial_api_token is None:
        raise exceptions.TokenServiceMissingInitialApiTokenException()

    token_store = []
    read_zone_token, token_store = cloudflare_token_service.create_read_zone_token(
        cf_initial_api_token, account_id, token_store)
    logger.info("Token store after Create Read Zone Token >>>>> : %s", token_store)

    zone_id = helpers.get_zone_id(fqdn, read_zone_token)
    logger.info("fqdn: %s", fqdn)
    logger.info("Zone ID to be added into Domain Group: %s", zone_id)

    token_permissions = [{"name": "Account Settings Write", "scope": "account"}]
    token_name = f"Runner: {environment} zone apply {fqdn}"
    scoped_api_token, token_store = cloudflare_token_service.create_account_level_scoped_token(
            cf_initial_api_token, token_permissions, account_id, token_store, token_name
        )
    logger.info("Token store after Create Account Level Scoped Token >>>>>>>> : %s", token_store)

    try:
        update_domain_group_response = update_domain_group(account_id, domain_group_id, zone_id, scoped_api_token)
        logger.info("Updated Resource Group Response: %s", update_domain_group_response)
        return update_domain_group_response
    except Exception as e:
        logger.error("Failed to add zone %s to domain group %s for account ID %s: %s", zone_id, domain_group_id, account_id, e)
        raise exceptions.CloudflareIAMServiceException("Failed to add zone to domain group")
    finally:
        cf_initial_api_token = helpers.check_initial_token(environment)
        deleted_tokens = cloudflare_token_service.delete_all_tokens(
            cf_initial_api_token, token_store
        )
        remaining = list(set(token_store) - set(deleted_tokens))
        logger.info("Cloudflare active scoped tokens: %s", remaining)
