"""
Service for Hashicorp Vault related operations
"""

import requests
import logging
from runner.src import api_constant
from runner.src import exceptions

logger = logging.getLogger(__name__)

def get_vault_token() -> str:
    """
    Get Vault token using LDAP authentication
    Args:
        None
    Returns:
        Vault token (str): The vault token generated using LDAP authentication
    """
    vault_url = api_constant.VAULT_URL
    ldap_auth_path = api_constant.VAULT_LDAP_AUTH_PATH
    username = api_constant.VAULT_LDAP_AUTH_USERNAME
    passwrd = api_constant.VAULT_LDAP_AUTH_PASSWORD

    full_url = f"{vault_url}/{ldap_auth_path}/{username}"
    body = {'password': passwrd}

    logger.info("Generating vault token from ldap user/pass....")

    try:
        response = requests.post(full_url , json=body, verify=True)
        logger.info("response from get_vault_token... %s", response)
        response_json = response.json()
        response.raise_for_status()
    except Exception as e:
        logger.error("Error requesting vault token %s", e)
        raise exceptions.HashicorpVaultServiceException("Error requesting vault token.")

    return response_json['auth']['client_token']


def read_secret_from_vault(full_url: str, vault_token: str, secret_to_read: str) -> str:
    """
    Read Vault Secret

    Args:
        full_url (str): The complete vault URL with mount, namespace and secret path
        vault_token (str): The vault token to authenticate the API call towards Hashicorp Vault
        secret_to_read (str): The secret that needs to be read from the vault
    Returns:
        secret_value (str): Value of the stored secret in Vault
    """
    get_request_headers = {
        "X-Vault-Token": vault_token
        }

    try:
        read_vault_response = requests.get(full_url, headers=get_request_headers, verify=True)
        secret_value = read_vault_response.json()['data']['data'][secret_to_read]
    except Exception as e:
        logger.error("Error reading vault secret: %s", e)
        raise exceptions.HashicorpVaultServiceException("Error reading vault secret.")

    return secret_value


def update_secret_in_vault(full_url: str, vault_token: str, secret_to_update: str, secret_value: str) -> dict:
    """
    Update Vault Secret
    Args:
        full_url (str): The complete vault URL with mount, namespace and secret path
        vault_token (str): The vault token to authenticate the API call towards Hashicorp Vault
        secret_to_update (str): The secret key name that needs to be updated
        secret_value (str): The secret value that will be updated
    Returns:
        write_vault_response (dict): The response from the vault API call to update the secret
    """
    headers = {
        "X-Vault-Token": vault_token,
        "Content-Type": "application/merge-patch+json"
        }

    payload_data = {
        "data": {
            secret_to_update: secret_value
            }
     }

    try:
        write_vault_response = requests.patch(url=full_url, headers=headers, json=payload_data, verify=True)
        logger.info("write_vault_response: %s", write_vault_response)
        write_vault_response_json = write_vault_response.json()
    except Exception as e:
        logger.error("Error updating vault secret: %s", e)
        raise exceptions.HashicorpVaultServiceException ("Error updating vault secret.")

    return write_vault_response_json
