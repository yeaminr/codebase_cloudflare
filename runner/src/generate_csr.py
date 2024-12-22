#!/usr/bin/env python3

import os
import json
import httpx
from cf.python.src import constants
from cf.python.src import helpers


# https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/
# https://developers.cloudflare.com/cloudflare-for-platforms/cloudflare-for-saas/security/certificate-management/custom-certificates/certificate-signing-requests/


def get_tenant_input(tenant_input_file: str) -> dict:
    """
    Validate that the provided path to the tenant input file is valid
    Check file exists and has all the required parameters
    Return contents of the file

    Parameters:
    tenant_input_file: str: path to the tenant input file

    Returns:
    dict: contents of the tenant input file

    Errors:
    FileNotFoundError: if the file does not exist
    ValueError: if the file does not have all the required parameters
    """
    required_keys = ["country", "state", "locality", "organization",
                     "organizational_unit", "common_name", "sans", "key_type"]
    tenant_input = helpers.validate_yaml_file(tenant_input_file, required_keys)

    return tenant_input


def create_read_zone_token(create_token: str, account_id: str) -> str:
    """
    create a token with read zone permissions
    Parameters:
    create_token: str: token created in Cloudflare using the Create Additional Tokens template
    account_id: str: account ID

    Returns:
    str: token that has permission to read zones within provided account
    """
    permission_names = ["Zone Read"]
    permission_groups = helpers.get_permission_groups(
        create_token, permission_names)
    policies = [{
        "effect": "allow",
        "permission_groups": permission_groups,
        "resources": {
            # only read zones within provided account
            f"com.cloudflare.api.account.{account_id}": "*"
        }
    }]

    ttl = constants.TOKEN_TTL_MINUTES
    zone_read_token = helpers.create_api_token(create_token, "READ ZONE TOKEN", policies, ttl)
    return zone_read_token


def create_ssl_token(create_token: str, zone_id: str) -> str:
    """
    create a token with permissions to edit SSL and Certificates
    Parameters:
    create_token: str: token created in Cloudflare using the Create Additional Tokens template
    zone_id: str: zone ID

    Returns:
    str: token that has permission to edit SSL and Certificates within provided account
    """
    permission_names = ["SSL and Certificates Write"]
    permission_groups = helpers.get_permission_groups(
        create_token, permission_names)
    policies = [{
        "effect": "allow",
        "permission_groups": permission_groups,
        "resources": {
            # only be able to write SSL and Certificates settings within provided zone
            f"com.cloudflare.api.account.zone.{zone_id}": "*"
        }
    }]

    ttl = constants.TOKEN_TTL_MINUTES
    ssl_write_token = helpers.create_api_token(create_token, "WRITE SSL CERT", policies, ttl)
    return ssl_write_token


def generate_csr(ssl_write_token: str, zone_id: str, tenant_input: dict) -> tuple:
    """
    Generate the CSR using the provided tenant input in the provided zone
    NOTE: SDK for CSR generation is not available yet. Using the httpx lib to make the API Call

    Parameters:
    ssl_write_token: str: token that has permission to edit SSL and Certificates within provided account
    zone_id: str: zone ID
    tenant_input: dict: tenant input details

    Returns:
    str: CSR generated
    """
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/custom_csrs"

    # for account level CSR
    # https://dash.cloudflare.com/api/v4/accounts/63e7d66d5951f05ac890f03a320647c1/custom_csrs
    # {"country":"AU","state":"NSW","locality":"Sydney","organization":"CBA","organizational_unit":"SauravOrg","common_name":"autopoc1.evolveatcommbank.com.au","sans":["autopoc1.evolveatcommbank.com.au"],"name":"SauravTest","description":"Test","key_type":"rsa2048","scope":"Account"}


    payload = tenant_input
    headers = {
        "Content-Type": "application/json",
        'Authorization': f"Bearer {ssl_write_token}"
    }
    try:
        response = httpx.post(url, json=payload, headers=headers)
        response.raise_for_status()
    except httpx.HTTPError as e:
        raise ValueError(
            f"Failed to generate CSR! Error: {e}")

    response = response.json()
    if "result" not in response:
        raise ValueError(
            f"Failed to generate CSR! Missing key 'result': {response}")

    result = response["result"]
    if "csr" not in result:
        raise ValueError(
            f"Failed to generate CSR! Missing key 'csr: {response}")
    if "id" not in result:
        raise ValueError(
            f"Failed to generate CSR! Missing key 'id: {response}")

    return result["id"], result["csr"]


def main():
    """ 
    Main function. Retrieve all the required environment variables
    """
    # get account ID
    account_id: str = os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
    # get zone ID
    zone_name: str = os.getenv("CLOUDFLARE_ZONE_NAME", "")
    # token created in Cloudflare using the Create Additional Tokens template
    create_token: str = os.getenv("CLOUDFLARE_INITIAL_API_TOKEN", "")
    # YAML file with CSR details
    tenant_input_file: str = os.getenv("TENANT_YAML_FILE_PATH", "")
    # temp file to store variables
    vars_output_file: str = os.getenv("TEMP_PYTHON_VARIABLE_FILE", "temp_vars.json")

    if not account_id:
        raise ValueError(
            "Environment variable CLOUDFLARE_ACCOUNT_ID is not set! Please set it to continue.")
    if not zone_name:
        raise ValueError(
            "Environment variable CLOUDFLARE_ZONE_NAME is not set! Please set it to continue.")
    if not create_token:
        raise ValueError(
            "Environment variable CLOUDFLARE_INITIAL_API_TOKEN is not set! "
            "Please set it to continue.")
    if not tenant_input_file:
        raise ValueError(
            "Environment variable TENANT_YAML_FILE_PATH is not set! Please set it to continue.")

    tenant_input: dict = get_tenant_input(tenant_input_file)

    zone_read_token: str = create_read_zone_token(create_token, account_id)
    zone_id: str = helpers.get_zone_id(zone_name, zone_read_token)
    ssl_write_token: str = create_ssl_token(create_token, zone_id)
    csr_id, csr = generate_csr(ssl_write_token, zone_id, tenant_input)

    # set the environment variable with the generated CSR
    with open(vars_output_file, "w") as f:
        data = {
            "CLOUDFLARE_GENERATED_CSR": csr,
            "CLOUDFLARE_CSR_ID": csr_id
        }
        json.dump(data, f)


if __name__ == "__main__":
    main()
