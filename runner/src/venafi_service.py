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
    expiresin: int,
    sans: list,
) -> str:
    """
    Refresh (creats/renews) a certificate from Venafi using the CSR generated

    Args:
    ----
    csr_input (dict): CSR input - common_name, csr, id
    env (str): environment to target
    signer (str): signer to use. can be either ext (digicert) or ext-ev (entrust)
                  prod must be ext-ev
    tso (str): TSO to use
    expiresin (int): expiry in days
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
        raise exceptions.VenafiServiceException("Venafi private key is not set")
    client_id = api_constant.VENAFI_CLIENT_ID
    cba_cert = cbacert(client_id, idp_private_key, prod=False)  # targetting non prod

    # default signer if not provided
    if not signer:
        if env.lower() == "prod":
            signer = "ext-ev"
        else:
            signer = "ext"

    # validate signer
    signer = signer.lower()
    if signer not in ["ext", "ext-ev"]:
        raise exceptions.VenafiServiceException(
            f"Invalid signer provided: {signer}. Must be either ext or ext-ev"
        )
    if signer == "ext" and env.lower() == "prod":
        raise exceptions.VenafiServiceException(
            "Invalid signer provided for prod environment. Must be ext-ev"
        )

    # issue certificate
    post_body = {
        "subject": csr_input["common_name"],
        "csr": csr_input["csr"],
        "cadn": signer,  # For internal cert do not use signer (cadn)
        "expiresin": expiresin,
        "name": csr_input["id"],
        "san": [{"TypeName": 2, "Name": san} for san in sans],
        "tsosn": tso,  # Needs to be tested with different TSO
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


def retrieve_venafi_cert(csr_input: dict, tso: str) -> str | None:
    """
    Retrieve a certificate from Venafi using the CSR generated

    Args:
    ----
    csr_input (dict): CSR input - common_name, csr, id
    tso (str): TSO to use

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
        raise exceptions.VenafiServiceException("Venafi private key is not set")
    client_id = api_constant.VENAFI_CLIENT_ID
    cba_cert = cbacert(client_id, idp_private_key, prod=False)  # targetting non prod
    retrieve_body = {
        "subject": csr_input["common_name"],
        "name": csr_input["id"],
        "tsosn": tso,  # Needs to be tested with different TSO
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
