"""
Module to interact with Venafi API for certificate management.
"""
import base64
import json
import logging
from cbacert import cbacert
from runner.src import exceptions
from runner.src import api_constant

logger = logging.getLogger(__name__)


def refresh_venafi_cert(
    csr_input: dict,
    env: str,
    signer: str,
    tso: str,
    sans: list,
) -> str:
    """
    Refresh (creats) a certificate from Venafi using the CSR generated

    Args:
    ----
    csr_input (dict): CSR input - common_name, csr, id
    env (str): environment to target
    signer (str): signer to use. can be either ext or ext-ev
    tso (str): TSO to use
    sans (list): list of SANs

    Returns:
    ----
    str: Signed certificate

    Raises:
    ----
    VenafiServiceException: If there is an error issuing certificate from Venafi
    """
    logger.info("Issuing certificate from Venafi")
    if (
        not csr_input
        or "common_name" not in csr_input
        or "csr" not in csr_input
        or "id" not in csr_input
    ):
        raise exceptions.VenafiServiceException(
            "CSR input is invalid. Must contain common_name, csr and id"
        )
    idp_private_key = api_constant.idp_private_key
    if not idp_private_key:
        raise exceptions.VenafiServiceException(
            "Venafi private key is not set")
    client_id = api_constant.venafi_client_id
    if not client_id:
        raise exceptions.VenafiServiceException("Venafi client ID is not set")

    # validate signer
    if not signer or signer not in ["ext", "ext-ev"]:
        raise exceptions.VenafiServiceException(
            f"Invalid signer provided: {signer}. Must be either ext or ext-ev"
        )

    is_prod = False
    if env.lower() == "prd":
        is_prod = True

    cba_cert = cbacert(client_id, idp_private_key, prod=is_prod)

    # issue certificate
    post_body = {
        "subject": csr_input["common_name"],
        "csr": csr_input["csr"],
        "cadn": signer,  # For internal cert do not use signer (cadn)
        "name": csr_input["id"],
        "san": [{"TypeName": 2, "Name": san} for san in sans],
        "tso": tso,  # Needs to be tested with different TSO
    }
    logger.info("Venafi payload: %s", post_body)
    try:
        logger.info("Refresh certificate from Venafi")
        signed_cert = cba_cert.refresh(json.dumps(post_body))
        if (
            "statuscode" in signed_cert
            and signed_cert["statuscode"] == 200
            and "certificatedata" in signed_cert
            and signed_cert["certificatedata"]
        ):
            cert_data = signed_cert["certificatedata"]
            cert = base64.b64decode(cert_data).decode("utf-8")
            return cert
        raise exceptions.VenafiServiceException(
            f"Venafi invalid response : {signed_cert}"
        )
    except Exception as e:
        raise exceptions.VenafiServiceException(
            f"Error issuing certificate from Venafi: {str(e)}"
        ) from e


def retrieve_venafi_cert(csr_input: dict, tso: str, env: str) -> str | None:
    """
    Retrieve a certificate from Venafi using the CSR generated

    Args:
    ----
    csr_input (dict): CSR input - common_name, csr, id
    tso (str): TSO to use
    env (str): environment to target

    Returns:
    ----
    str: Signed certificate

    Raises:
    ----
    VenafiServiceException: If there is an error retrieving certificate from Venafi
    """
    logger.info("Retrieving certificate from Venafi")
    if (
        not csr_input
        or "common_name" not in csr_input
        or "csr" not in csr_input
        or "id" not in csr_input
    ):
        raise exceptions.VenafiServiceException(
            "CSR input is invalid. Must contain common_name, csr and id"
        )
    idp_private_key = api_constant.idp_private_key
    if not idp_private_key:
        raise exceptions.VenafiServiceException(
            "Venafi private key is not set")
    client_id = api_constant.venafi_client_id
    if not client_id:
        raise exceptions.VenafiServiceException("Venafi client ID is not set")
    is_prod = False
    if env.lower() == "prd":
        is_prod = True
    cba_cert = cbacert(client_id, idp_private_key, prod=is_prod)
    retrieve_body = {
        "subject": csr_input["common_name"],
        "name": csr_input["id"],
        "tso": tso,  # Needs to be tested with different TSO
    }
    logger.info("Venafi payload: %s", retrieve_body)
    try:
        signed_cert = cba_cert.retrieve(json.dumps(retrieve_body))
        if (
            "statuscode" in signed_cert
            and signed_cert["statuscode"] == 200
            and "certificatedata" in signed_cert
            and signed_cert["certificatedata"]
        ):
            cert_data = signed_cert["certificatedata"]
            cert = base64.b64decode(cert_data).decode("utf-8")  # cert chain
            return cert
        return None
    except Exception as e:
        raise exceptions.VenafiServiceException(
            f"Error retrieving certificate from Venafi: {str(e)}"
        ) from e
