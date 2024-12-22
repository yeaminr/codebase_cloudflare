#!/usr/bin/env python3

import os
import json
import httpx
from cf.python.src import helpers
from cf.python.src import constants


# https://developers.cloudflare.com/fundamentals/api/how-to/create-via-api/


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
    zone_read_token = helpers.create_api_token(
        create_token, "READ ZONE TOKEN", policies, ttl)
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
    ssl_write_token = helpers.create_api_token(
        create_token, "WRITE SSL CERT", policies, ttl)
    return ssl_write_token


def upload_certificate(ssl_write_token: str, zone_id: str, csr_id: str,
                       certificate: str) -> dict:
    """
    Upload the signed certificate to the provided hostname

    Parameters:
    ssl_write_token: str: token that has permission to edit SSL and Certificates
    zone_id: str: zone ID
    hostname: str: a hostname within the provided zone ID to associate the certificate with
    csr_id: str: CSR ID of the CSR that created the certificate
    certificate: str: signed certificate    # certificate must be seperated with newline not \n
    """
    url = (
        f"https://api.cloudflare.com/client/v4/zones/{zone_id}/custom_certificates")

    payload = {
        "custom_csr_id": csr_id,
        "certificate": certificate,
        "type": "sni_custom",
        "bundle_method": "ubiquitous",
    }
    headers = {
        "Content-Type": "application/json",
        'Authorization': f"Bearer {ssl_write_token}"
    }
    try:
        response = httpx.post(url, json=payload, headers=headers)
        response.raise_for_status()
    except httpx.HTTPError as e:
        raise ValueError(
            f"Failed to upload certificate! Error: {e}")

    print("Successfully uploaded cert")
    return response.json()


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
    # get temp variables file
    vars_file: str = os.getenv("TEMP_PYTHON_VARIABLE_FILE", "temp_vars.json")

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
    if not os.path.exists(vars_file):
        raise ValueError(
            f"Vars file {vars_file} does not exist. "
            "Please run generate_csr.py first to generate this file.")

    zone_read_token: str = create_read_zone_token(create_token, account_id)
    zone_id: str = helpers.get_zone_id(zone_name, zone_read_token)
    ssl_write_token: str = create_ssl_token(create_token, zone_id)
    with open(vars_file, "r") as file:
        temp_vars = json.load(file)

    venafi_signed_certificate: str = temp_vars["VENAFI_SIGNED_CERTIFICATE"]

    csr_id = temp_vars["CLOUDFLARE_CSR_ID"]
    upload_certificate(ssl_write_token, zone_id,
                       csr_id, venafi_signed_certificate)


if __name__ == "__main__":
    main()
