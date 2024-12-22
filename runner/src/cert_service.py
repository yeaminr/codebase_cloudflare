import os
import logging
from datetime import datetime, timedelta
from collections import Counter
import yaml
import httpx
import base64
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src.model import InputModel, CertOutputModel
from runner.src import api_constant
from runner.src import github_service
from runner.src import exceptions
from runner.src import cloudflare_token_service
from runner.src import venafi_service
from cf.python.src import helpers

logger = logging.getLogger(__name__)


def get_auth_header(cf_token: str) -> dict:
    """
    Get the authentication header for Cloudflare API

    Parameters:
    cf_token: str: Cloudflare API token

    Returns:
    dict: authentication header
    """
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {cf_token}",
    }


def format_csr_input(csr_input: dict) -> dict:
    """
    Format the CSR input to match the required keys and values

    Parameters:
    csr_input: dict: CSR input

    Returns:
    dict: formatted CSR input

    Raises:
    CertificateServiceInvalidCSRException: if the required keys are missing or invalid
    """
    logger.info("Formatting CSR input %s", csr_input)
    for req_key in api_constant.CSR_REQUIRED_KEYS:
        if req_key not in csr_input.keys():
            raise exceptions.CertificateServiceInvalidCSRException(
                f"Missing required key '{req_key}' in CSR input"
            )
        csr_input[req_key] = csr_input[req_key].strip()

    for opt_key, opt_value in api_constant.CSR_OPTIONAL_KEYS.items():
        if opt_key in csr_input.keys():
            if csr_input[opt_key] not in opt_value:
                raise exceptions.CertificateServiceInvalidCSRException(
                    f"Invalid '{opt_key}' provided in CSR input"
                )
        else:
            csr_input[opt_key] = opt_value[0]

    return csr_input


def get_cert_parameters(repo_name: str, vars_path: str, branch_name: str) -> dict:
    """
    Get the certificate parameters from the vars file

    Parameters:
    repo_name: str: repository name
    vars_path: str: path to the vars file
    branch_name: str: branch name

    Returns:
    dict: certificate parameters

    Raises:
    exceptions.CertificateServiceException: if the API call fails
    """
    try:
        cert_input_url = github_service.get_download_url(
            repo_name, vars_path, branch_name
        )
        raw_yaml = github_service.get_file_content(cert_input_url, None)
        cert_parameters = yaml.safe_load(raw_yaml)
        if (
            "certs" not in cert_parameters
            or "renew_time" not in cert_parameters["certs"]
            or "tso" not in cert_parameters["certs"]
        ):
            raise exceptions.CertificateServiceException(
                f"Invalid cert parameters: {cert_parameters}"
            )
        return cert_parameters["certs"]
    except Exception as e:
        logger.error("Error getting cert parameters: %s", e)
        raise exceptions.CertificateServiceException(
            f"Error getting cert parameters from Github: {e}"
        ) from e


def list_cf_account_csr(cf_token: str, account_id: str) -> list:
    """
    List all the CSR in the provided account

    Parameters:
    cf_token: str: token that has permission to read SSL and Certificates
    account_id: str: account ID

    Returns:
    dict: list of CSR

    Raises:
    exceptions.CertificateServiceCFAPIException: if the API call fails or the response is invalid
    """
    logger.info("Listing all the CSR in the account %s", account_id)
    result = []
    page = 1
    while True:
        url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/custom_csrs?page={page}&per_page=50"
        try:
            response = httpx.get(url, headers=get_auth_header(cf_token))
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise exceptions.CertificateServiceCFAPIException(
                f"Failed to list CSR! Error: {e}"
            ) from e
        response_json = response.json()
        if "result" not in response_json:
            raise exceptions.CertificateServiceCFAPIException(
                f"Failed to list CSR! Missing key 'result': {response_json}"
            )
        if len(response_json["result"]) == 0:
            break
        result.extend(response_json["result"])
        total_pages = response_json.get("ResultInfo", {}).get(
            "total_pages"
        ) or response_json.get("result_info", {}).get("total_pages")
        if not total_pages:
            raise exceptions.CertificateServiceCFAPIException(
                f"Failed to list CSR! result info object not found for pagination : {response_json}"
            )
        if page >= total_pages:
            break
        page += 1
    # print(json.dumps(result, indent=4))
    return result


def get_cf_account_csr_by_input(
    cf_token: str, account_id: str, csr_parameters: dict
) -> dict | None:
    """
    Get the CSR details using the provided CSR input

    Parameters:
    cf_token: str: token that has permission to read SSL and Certificates
    account_id: str: account ID
    csr_parameters: dict: CSR input

    Returns:
    dict: CSR details
    """
    logger.info("Getting the CSR details")
    all_account_csrs = list_cf_account_csr(cf_token, account_id)
    for csr in all_account_csrs:
        if (
            Counter(csr["sans"]) == Counter(csr_parameters["sans"])
            and csr["common_name"] == csr_parameters["common_name"]
        ):
            return csr
    return None


def get_cf_zone_cert_by_csr(cf_token: str, zone_id: str, csr_id: str) -> dict | None:
    """
    Get the certificate details with latest expiration date using the provided CSR ID

    Parameters:
    cf_token: str: token that has permission to read SSL and Certificates
    zone_id: str: zone ID
    csr_id: str: CSR ID

    Returns:
    dict: certificate details
    """
    logger.info("Getting the Cert details by CSR id %s", csr_id)
    all_zone_certs = list_cf_zone_certificates(cf_token, zone_id)
    latest_expiry = datetime.now()
    valid_cert = None
    for certs in all_zone_certs:
        if certs["custom_csr_id"] == csr_id:
            cert_expires_on = datetime.strptime(
                certs["certificates"][0]["expires_on"], "%Y-%m-%dT%H:%M:%S.%fZ"
            )
            if cert_expires_on > latest_expiry:
                latest_expiry = cert_expires_on
                valid_cert = certs
    return valid_cert


def generate_cf_account_csr(cf_token: str, account_id: str, csr_input: dict) -> dict:
    """
    Generate the CSR using the provided input in the provided account

    Parameters:
    cf_token: str: token that has permission to edit SSL and Certificates within provided account
    account_id: str: account ID
    csr_input: dict: CSR input details

    Returns:
    dict: CSR generated

    Raises:
    exceptions.CertificateServiceCFAPIException: if the API call fails or the response is invalid
    """
    logger.info("Generating Account CSR")
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/custom_csrs"
    payload = csr_input
    try:
        response = httpx.post(url, json=payload, headers=get_auth_header(cf_token))
        response.raise_for_status()
    except httpx.HTTPError as e:
        raise exceptions.CertificateServiceCFAPIException(
            f"Failed to generate CSR! Error: {e}"
        ) from e
    response_json = response.json()
    if (
        "result" not in response_json
        or "csr" not in response_json["result"]
        or "id" not in response_json["result"]
    ):
        raise exceptions.CertificateServiceCFAPIException(
            f"Failed to generate CSR! Invalid response json : {response_json}"
        )
    logger.info("Successfully generated CSR with id: %s", response_json["result"]["id"])
    return response_json["result"]


def list_cf_zone_certificates(cf_token: str, zone_id: str) -> list:
    """
    List all the certificates in the provided zone

    Parameters:
    cf_token: str: token that has permission to read SSL and Certificates
    zone_id: str: zone ID

    Returns:
    dict: list of certificates

    Raises:
    ValueError: if the API call fails
    """
    logger.info("Listing all the certificates in the zone")
    result = []
    page = 1
    while True:
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/ssl/certificate_packs?page={page}&per_page=50"
        try:
            response = httpx.get(url, headers=get_auth_header(cf_token))
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise exceptions.CertificateServiceCFAPIException(
                f"Failed to list certificates! Error: {e}"
            ) from e
        response_json = response.json()
        if "result" not in response_json:
            raise exceptions.CertificateServiceCFAPIException(
                f"Failed to list Certificate Missing key 'result': {response_json}"
            )
        if len(response_json["result"]) == 0:
            break
        result.extend(response_json["result"])
        total_pages = response_json.get("ResultInfo", {}).get(
            "total_pages"
        ) or response_json.get("result_info", {}).get("total_pages")
        if not total_pages:
            raise exceptions.CertificateServiceCFAPIException(
                f"Failed to list Certificate! result info object not found for pagination : {response_json}"
            )
        if page >= total_pages:
            break
        page += 1
    return result


def upload_cf_zone_certificate(
    cf_token: str, zone_id: str, csr_id: str, certificate: str
) -> dict:
    """
    Upload the signed certificate to the provided hostname

    Parameters:
    cf_token: str: token that has permission to edit SSL and Certificates
    zone_id: str: zone ID
    csr_id: str: CSR ID of the CSR that created the certificate
    certificate: str: signed certificate    # certificate must be seperated with newline not \n
    """
    logger.info("Uploading certificate to Cloudflare")
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/custom_certificates"

    payload = {
        "custom_csr_id": csr_id,
        "certificate": certificate,
        "type": "sni_custom",
        "bundle_method": "ubiquitous",
    }
    logger.info(payload)
    try:
        response = httpx.post(url, json=payload, headers=get_auth_header(cf_token))
        response.raise_for_status()
    except httpx.HTTPError as e:
        raise exceptions.CertificateServiceCFAPIException(
            f"Failed to upload certificate! Error: {e}"
        ) from e
    logger.info("Successfully uploaded cert")
    return response.json()["result"]


def create_cert(
    token: str, env: str, zone_id: str, csr_result: dict, cert_parameters: dict
) -> dict | None:
    """
    Create a certificate
    """
    cert = venafi_service.refresh_venafi_cert(
        csr_result,
        env,
        cert_parameters.get("signer", ""),
        cert_parameters.get("tso"),
        cert_parameters.get("renew_time"),
        cert_parameters.get("sans"),
    )
    logger.info("Certificate issued successfully")
    if cert:
        logger.info("Uploading certificate")
        cert_response = upload_cf_zone_certificate(
            token,
            zone_id,
            csr_result["id"],
            cert.replace("\r", ""),
        )
        logger.info("CERT UPLOAD RESPONSE: %s", cert_response)
        return cert_response
    return None


def renew_cert(cert: dict, renew_time: int) -> bool:
    """
    Check if the certificate is expiring soon

    Parameters:
    cert: dict: certificate details
    renew_time: int: days before the certificate expires to renew

    Returns:
    bool: True if the certificate is expiring soon, False otherwise

    Raises:
    exceptions.CertificateServiceInvalidCertException: if the certificate details are invalid
    """
    if (
        "certificates" not in cert
        or len(cert["certificates"]) == 0
        or "expires_on" not in cert["certificates"][0]
    ):
        raise exceptions.CertificateServiceInvalidCertException(
            f"Invalid certificate details: {cert}"
        )
    cert_expires_on = datetime.strptime(
        cert["certificates"][0]["expires_on"], "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    if cert_expires_on < datetime.now() + timedelta(days=renew_time):
        logger.info(
            "Certificate is expiring on %s. Renewing the certificate",
            cert["certificates"][0]["expires_on"],
        )
        return True
    return False


def plan_cert(input_model: InputModel, jwt_token_info: JWTTokenInfo) -> CertOutputModel:
    """
    Plan the certificate request.
    Check if the CSR exists in the account by comparing the name and SANs.
    If the CSR does not exist,
        Return csr and cert to be created
    If the CSR exists, check if the certificate exists for the CSR.
    If the certificate does not exist,
        Return csr exists and cert to be created
    If the certificate exists, check if the certificate is expiring soon.
    If the certificate is expiring soon,
        Return csr exists and cert to be renewed
    If the certificate is not expiring soon,
        Return csr and cert exists

    Parameters:
    input_model: InputModel: input model from main function
    jwt_token_info: JWTTokenInfo: JWT token info with GitHub details

    Returns:
    CertOutputModel: response
    """
    try:
        cert_output = CertOutputModel()
        token_store = cloudflare_token_service.set_cloudflare_scoped_token(input_model)
        cloudflare_scoped_token = os.environ.get("CLOUDFLARE_API_TOKEN", None)
        cert_parameters = get_cert_parameters(
            jwt_token_info.repo_name,
            input_model.input_vars_path,
            jwt_token_info.branch_name,
        )
        csr_parameters = format_csr_input(cert_parameters)
        logger.info("Cert params %s", cert_parameters)
        zone_id = helpers.get_zone_id(input_model.fqdn, cloudflare_scoped_token)
        exist_csr = get_cf_account_csr_by_input(
            cloudflare_scoped_token,
            input_model.account_id,
            csr_parameters,
        )
        if not exist_csr:
            logger.info("CSR not found")
            csr_result = csr_parameters
        else:
            logger.info("CSR found. Using the existing CSR %s", exist_csr["id"])
            cert_output.csr_status = "exist"
            csr_result = exist_csr
            cert_output.csr = base64.b64encode(
                csr_result["csr"].encode("utf-8")
            ).decode("utf-8")
            cert_output.csr_id = csr_result["id"]
            logger.info(csr_result)
            cert = get_cf_zone_cert_by_csr(
                cloudflare_scoped_token, zone_id, csr_result["id"]
            )
            if not cert:
                logger.info("Cert does not exist for the CSR %s ", csr_result["id"])
                venafi_cert = venafi_service.retrieve_venafi_cert(
                    csr_result, cert_parameters.get("tso")
                )
                if venafi_cert:
                    cert_output.venafi_status = "exist"
            else:
                if renew_cert(cert, cert_parameters["renew_time"]):
                    cert_output.cert_status = "to_be_renewed"
                    logger.info(
                        "Certificate is valid and expiring soon. Planning the refresh"
                    )
                else:
                    cert_output.cert_status = "exist"
                    logger.info("Certificate is valid and not expiring soon")
                cert_output.venafi_status = "exist"
                cert_output.expiresin = cert["certificates"][0]["expires_on"]
    except Exception as e:
        logger.error("Error planning certificate: %s", e)
        raise exceptions.CertificateServiceException(
            f"Error planning certificate: {e}"
        ) from e
    finally:
        try:
            if token_store:
                cloudflare_token_service.delete_all_tokens(
                    api_constant.cf_initial_api_token, token_store
                )
        except Exception as e:
            logger.error("Error deleting the token: %s", e)
            cert_output.error = str(e)
    cert_output.common_name = csr_result["common_name"]
    cert_output.sans = csr_result["sans"]
    return cert_output


def process_cert(
    input_model: InputModel, jwt_token_info: JWTTokenInfo
) -> CertOutputModel:
    """
    Process the certificate request.
    Check if the CSR exists in the account by comparing the name and SANs.
    If the CSR does not exist,
        Generate a new CSR
        Create a new certificate by calling Venafi
        Upload the certificate to Cloudflare.
    If the CSR exists, check if the certificate exists for the CSR.
    If the certificate does not exist,
        Create a new certificate by calling Venafi.
        Upload the certificate to Cloudflare.
    If the certificate exists, check if the certificate is expiring soon.
    If the certificate is expiring soon,
        Renew the certificate by calling Venafi.
        Upload the certificate to Cloudflare.
    If the certificate is not expiring soon, skip the refresh.


    Parameters:
    input_model: InputModel: input model from main function
    jwt_token_info: JWTTokenInfo: JWT token info with GitHub details

    Returns:
    CertOutputModel: response
    """
    try:
        cert_output = CertOutputModel()
        token_store = cloudflare_token_service.set_cloudflare_scoped_token(input_model)
        cloudflare_scoped_token = os.environ.get("CLOUDFLARE_API_TOKEN", None)
        cert_parameters = get_cert_parameters(
            jwt_token_info.repo_name,
            input_model.input_vars_path,
            jwt_token_info.branch_name,
        )
        csr_parameters = format_csr_input(cert_parameters)
        env = input_model.environment.value
        logger.info("Cert params %s", cert_parameters)
        zone_id = helpers.get_zone_id(input_model.fqdn, cloudflare_scoped_token)
        exist_csr = get_cf_account_csr_by_input(
            cloudflare_scoped_token,
            input_model.account_id,
            csr_parameters,
        )
        if not exist_csr:
            logger.info("CSR not found. Generating new CSR")
            csr_result = generate_cf_account_csr(
                cloudflare_scoped_token,
                input_model.account_id,
                csr_parameters,
            )
            response = create_cert(
                cloudflare_scoped_token, env, zone_id, csr_result, cert_parameters
            )
            cert_output.csr_status = "created"
            cert_output.cert_status = "created"
            cert_output.venafi_status = "created"
            cert_output.expiresin = response["expires_on"]
        else:
            logger.info("CSR found. Using the existing CSR %s", exist_csr["id"])
            cert_output.csr_status = "exist"
            csr_result = exist_csr
            cert = get_cf_zone_cert_by_csr(
                cloudflare_scoped_token, zone_id, csr_result["id"]
            )
            if not cert:
                logger.info("Cert does not exist for the CSR %s", csr_result["id"])
                response = create_cert(
                    cloudflare_scoped_token,
                    env,
                    zone_id,
                    csr_result,
                    cert_parameters,
                )
                cert_output.cert_status = "created"
                cert_output.venafi_status = "refreshed"
                cert_output.expiresin = response["expires_on"]
            else:
                cert_output.venafi_status = "exist"
                if renew_cert(cert, cert_parameters["renew_time"]):
                    response = create_cert(
                        cloudflare_scoped_token,
                        env,
                        zone_id,
                        csr_result,
                        cert_parameters,
                    )
                    cert_output.cert_status = "renewed"
                    cert_output.expiresin = response["expires_on"]
                else:
                    cert_output.cert_status = "exist"
                    cert_output.expiresin = cert["certificates"][0]["expires_on"]
                    logger.info("Certificate is valid. Skipping the refresh")
    except Exception as e:
        logger.error("Error processing certificate: %s", e)
        raise exceptions.CertificateServiceException(
            f"Error processing certificate: {e}"
        ) from e
    finally:
        try:
            if token_store:
                cloudflare_token_service.delete_all_tokens(
                    api_constant.cf_initial_api_token, token_store
                )
        except Exception as e:
            logger.error("Error deleting the token: %s", e)
            cert_output.error = str(e)
    cert_output.csr = base64.b64encode(csr_result["csr"].encode("utf-8")).decode(
        "utf-8"
    )
    cert_output.csr_id = csr_result["id"]
    cert_output.common_name = csr_result["common_name"]
    cert_output.sans = csr_result["sans"]
    return cert_output
