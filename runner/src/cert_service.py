"""
Module to manage edge certificates in Cloudflare using the Cloudflare API.
"""

import os
import json
import logging
from collections import Counter
import yaml
import httpx
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src.model import InputModel, CertOutputModel
from runner.src import api_constant
from runner.src import github_service
from runner.src import exceptions
from runner.src import cloudflare_token_service
from runner.src import venafi_service
from runner.src import working_dir as wd
from runner.src import terraform_service
from runner.src import helpers

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


def format_cert_input(cert_params: dict, env: str) -> dict:
    """
    Format the CERT input to match the required keys and values

    Parameters:
    cert_input: dict: CERT input
    env: str: environment (dev, tst, stg, prd)

    Returns:
    dict: formatted CERT input

    Raises:
    CertificateServiceInvalidCertException: if the required keys are missing or invalid
    """
    logger.info("CERT input from yaml %s", cert_params)
    if "certs" not in cert_params:
        raise exceptions.CertificateServiceInvalidCertException(
            "Missing required key 'certs' in CERT input"
        )
    priority_enabled = cert_params.get("priority_enabled", False)
    cert_input = cert_params["certs"]
    names = []
    for cert in cert_input:
        # Required keys
        if not all(x in cert.keys() for x in api_constant.CERT_REQUIRED_KEYS):
            raise exceptions.CertificateServiceInvalidCertException(
                "Missing required keys in CERT input"
            )

        if (priority_enabled and "priority" not in cert.keys()) or (
            not priority_enabled and "priority" in cert.keys()
        ):
            raise exceptions.CertificateServiceInvalidCertException(
                "Invalid priority key in CERT input"
            )

        # Optional keys
        for key, value in api_constant.CERT_OPTIONAL_KEYS.items():
            if key not in cert.keys():
                cert[key] = value

        # default signer if not provided
        signer = cert.get("signer", "").lower()
        if not signer:
            if env.lower() == "prd":
                signer = "ext-ev"
            else:
                signer = "ext"

        # validate signer
        if signer not in ["ext", "ext-ev"]:
            logger.info("Signer in cert not ext or ext-ev")
            raise exceptions.CertificateServiceException(
                f"Invalid signer provided: {signer}. Must be either ext or ext-ev"
            )

        # set the signer
        cert["signer"] = signer

        # check organization is expected
        org = cert.get("organization", "")
        allowed_orgs = api_constant.CERT_CSR_ORG_VALUES[signer]
        if org not in allowed_orgs:
            logger.info(
                "Provided organization is not allowed for the selected signer %s. Allowed orgnization's are: %s",
                signer,
                allowed_orgs,
            )
            raise exceptions.CertificateServiceException(
                "Provided organization is not allowed for the selected signer"
            )

        names.append(cert["name"])  # For duplicate check

    # Check for duplicate names
    if len(names) != len(set(names)):
        raise exceptions.CertificateServiceInvalidCertException(
            f"Duplicate names found in CERT input {names}"
        )
    return cert_params


def list_cf_account_csr(cf_token: str, account_id: str) -> list:
    """
    List all the CSR in the provided account. The API returns 50 results per page.
    We need to loop through all the pages to get all the results.

    Parameters:
    cf_token: str: token that has permission to read SSL and Certificates
    account_id: str: account ID

    Returns:
    dict: list of CSR

    Raises:
    CertificateServiceCFAPIException: if the API call fails or the response is invalid
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
        if response.status_code != 200 or "result" not in response_json:
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
                "Failed to list CSR! result info object not found for pagination: "
                f"{response_json}"
            )
        if page >= total_pages:
            break
        page += 1
    return result


def get_cf_account_csr_by_input(
    cert_parameters: dict, all_account_csrs: list
) -> dict | None:
    """
    Get the CSR details using the provided Cert input from YAML

    Parameters:
    cf_token: str: token that has permission to read SSL and Certificates
    account_id: str: account ID
    cert_parameters: dict: CERT input from YAML

    Returns:
    dict: CSR details
    """
    logger.info("Getting the CSR details by cert parameters")
    for csr in all_account_csrs:
        if (
            Counter(csr["sans"]) == Counter(cert_parameters["sans"])
            and csr["common_name"] == cert_parameters["common_name"]
            and csr["name"] == cert_parameters["name"]
        ):
            logger.info("CSR found with id %s", csr["id"])
            return csr
    return None


def get_cf_zone_cert_by_csr(csr_id: str, all_zone_certs: list) -> dict | None:
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
    for cert in all_zone_certs:
        if cert["custom_csr_id"] == csr_id:
            cert["custom_csr_id"] = csr_id
            cert["cert_pack_id"] = cert["id"]
            return cert
    return None


def get_cf_zone_cert_by_id(
    cf_token: str, zone_id: str, cert_pack_id: str
) -> dict | None:
    """
    Get the certificate details using the provided CERT pack ID

    Parameters:
    cf_token: str: token that has permission to read SSL and Certificates
    zone_id: str: zone ID
    cert_pack_id: str: CERT pack ID

    Returns:
    dict: certificate details
    """
    logger.info("Getting the Cert details by Cert pack id %s", cert_pack_id)
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/custom_certificates/{cert_pack_id}"
    try:
        response = httpx.get(url, headers=get_auth_header(cf_token))
        response.raise_for_status()
    except httpx.HTTPError as e:
        # CF returning 400 or 404 if cert not found
        if response.status_code in [400, 404]:
            logger.info("Cert not found with cert pack id %s", cert_pack_id)
            return None
        raise exceptions.CertificateServiceCFAPIException(
            f"Failed to get cert using cert pack id : {e}"
        ) from e
    response_json = response.json()
    logger.info("Cert details by Cert pack id %s", response_json)
    if "result" not in response_json:
        return None
    return response_json["result"]


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
    CertificateServiceCFAPIException: if the API call fails or the response is invalid
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
        response.status_code != 201
        or "result" not in response_json
        or "csr" not in response_json["result"]
        or "id" not in response_json["result"]
    ):
        raise exceptions.CertificateServiceCFAPIException(
            f"Invalid response json for CSR generation: {response_json}"
        )
    logger.info("Successfully generated CSR with id: %s", response_json["result"]["id"])
    return response_json["result"]


def list_cf_zone_certificates(cf_token: str, zone_id: str) -> list:
    """
    List all the certificates in the provided zone. The API returns 50 results per page.
    We need to loop through all the pages to get all the results.

    Parameters:
    cf_token: str: token that has permission to read SSL and Certificates
    zone_id: str: zone ID

    Returns:
    dict: list of certificates

    Raises:
    CertificateServiceCFAPIException: if the API call fails
    """
    logger.info("Listing all the certificates in the zone")
    result = []
    page = 1
    while True:
        url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/custom_certificates?page={page}&per_page=50"
        try:
            response = httpx.get(url, headers=get_auth_header(cf_token))
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise exceptions.CertificateServiceCFAPIException(
                f"Failed to list certificates! Error: {e}"
            ) from e
        response_json = response.json()
        if response.status_code != 200 or "result" not in response_json:
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
                "Failed to list Certificate! "
                f"Result info object not found for pagination: {response_json}"
            )
        if page >= total_pages:
            break
        page += 1
    return result


def upload_cf_zone_certificate(
    cf_token: str, zone_id: str, csr_id: str, certificate: str
) -> dict:
    """
    Upload the signed certificate to the provided zone_id

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
    if response.status_code != 200 or "result" not in response.json():
        raise exceptions.CertificateServiceCFAPIException(
            f"Failed to upload certificate to Cloudflare: {response.json()}"
        )
    logger.info("Successfully uploaded cert")
    return response.json()["result"]


def remove_cf_zone_certificate(cf_token: str, zone_id: str, cert_pack_id: str) -> dict:
    """
    Remove the certificate from the provided zone_id

    Parameters:
    cf_token: str: token that has permission to edit SSL and Certificates
    zone_id: str: zone ID
    cert_pack_id: str: certificate pack ID

    Returns:
    dict: response from the API

    Raises:
    CertificateServiceCFAPIException: if the API call fails
    """
    logger.info("Remove certificate from Cloudflare")
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/custom_certificates/{cert_pack_id}"
    try:
        response = httpx.delete(url, headers=get_auth_header(cf_token))
        response.raise_for_status()
    except httpx.HTTPError as e:
        raise exceptions.CertificateServiceCFAPIException(
            f"Failed to remove certificate! Error: {e}"
        ) from e
    logger.info("Successfully removed old cert")
    response_json = response.json()
    if response.status_code != 200 or "result" not in response_json:
        raise exceptions.CertificateServiceCFAPIException(
            f"Failed to remove Certificate : {response_json}"
        )
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
        cert_parameters["signer"],
        cert_parameters["tso"],
        cert_parameters["sans"],
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


def get_cert(input_model: InputModel, jwt_token_info: JWTTokenInfo) -> CertOutputModel:
    """
    Get the certificate details from the state file

    Parameters:
    input_model: InputModel: input model from main function
    jwt_token_info: JWTTokenInfo: JWT token info with GitHub details

    Returns:
    CertOutputModel: response
    """
    try:
        cwd = wd.create_dir()
        if cwd is None:
            raise exceptions.CertificateServiceException(
                "Failed to create working directory"
            )
        cert_parameters = load_cert_parameters(input_model, jwt_token_info, cwd)
        logger.info("Formatted CERT params %s", cert_parameters)
        token_store, cloudflare_scoped_token = cloudflare_token_service.set_cloudflare_scoped_token(input_model)
        cert_ids_from_state = get_cert_tf_state(cwd, input_model, "full_cert_details")
        cert_output_response = process_cert_plan(cert_parameters, input_model, cloudflare_scoped_token)
        cert_output_response = remove_cert_plan(
            cert_ids_from_state, cert_output_response
        )
        logger.info("Terraform output type: %s", cert_output_response)
        logger.info("cert_ids_from_state: %s", cert_ids_from_state)
    except Exception as e:
        logger.error("Error planning certificate: %s", e)
        raise exceptions.CertificateServiceException(
            f"Error planning certificate: {e}"
        ) from e
    finally:
        try:
            if token_store:
                cf_initial_api_token = helpers.check_initial_token(input_model.environment)
                cloudflare_token_service.delete_all_tokens(
                    cf_initial_api_token, token_store
                )
        except Exception as e:
            logger.error("Error deleting the token: %s", e)
        try:
            if cwd:
                wd.delete_dir(cwd)
        except Exception as e:
            logger.error("Error deleting the working directory: %s", e)
    return cert_output_response


def process_priority_plan(
    cert_param: dict,
    cert_result: dict,
    cert_output: CertOutputModel,
) -> None:
    """
    Process the priority plan for the certificate.
    Compare the current priority with the desired priority and update the output accordingly.
    If the current priority is different from the desired priority, update the output with the change.
    If the current priority is the same as the desired priority, set the output to the current priority.

    Parameters:
    cert_param: dict: certificate parameters from the input yaml
    cert_result: dict: certificate result from the Cloudflare API
    cert_output: CertOutputModel: certificate output model to be updated which contains plan details
    """
    current_priority = cert_result.get("priority", 0)
    desired_priority = cert_param.get("priority", 0)

    if current_priority != desired_priority:
        cert_output.priority = f"{current_priority} -> {desired_priority}"
    else:
        cert_output.priority = str(current_priority)


def process_cert_plan(cert_parameters: dict, input_model: InputModel, cloudflare_scoped_token: str) -> list:
    """
    Process the certificate plan.
    Check if the CSR exists in the account by comparing the name and SANs.
    If the CSR does not exist, update `csr_id` with `To be generated`.
    If the CSR exists, update `csr_id` with CSR id.
    If the certificate does not exist, update `cert_pack_id` with `To be generated`..
    If the certificate exists, update `cert_pack_id` with CERT pack id.

    Parameters:
    cert_parameters: dict: certificate parameters
    input_model: InputModel: input model

    Returns:
    list: certificate output response as dict
    """
    cert_output_response = []
    zone_id = helpers.get_zone_id(input_model.fqdn, cloudflare_scoped_token)
    all_account_csrs = list_cf_account_csr(
        cloudflare_scoped_token, input_model.account_id
    )
    all_zone_certs = list_cf_zone_certificates(cloudflare_scoped_token, zone_id)
    for cert_param in cert_parameters["certs"]:
        cert_output = CertOutputModel()
        exist_csr = get_cf_account_csr_by_input(
            cert_param,
            all_account_csrs,
        )
        if not exist_csr:
            logger.info("CSR not found. Adding TO_BE_GENERATED to plan")
            cert_output.csr_id = api_constant.TO_BE_GENERATED
            cert_output.cert_pack_id = api_constant.TO_BE_GENERATED
        else:
            logger.info("CSR found. Using the existing CSR %s", exist_csr["id"])
            csr_result = exist_csr
            cert_output.csr_id = csr_result["id"]
            cert_result = get_cf_zone_cert_by_csr(
                csr_result["id"],
                all_zone_certs,
            )
            if not cert_result:
                logger.info("Cert does not exist for the CSR %s", csr_result["id"])
                cert_output.cert_pack_id = api_constant.TO_BE_GENERATED
            else:
                cert_output.expires_on = cert_result["expires_on"]
                cert_output.cert_pack_id = cert_result["cert_pack_id"]
                if cert_parameters.get("priority_enabled", False):
                    process_priority_plan(cert_param, cert_result, cert_output)
                logger.info("Certificate is valid.")
        cert_output.common_name = cert_param["common_name"]
        cert_output.sans = cert_param["sans"]
        cert_output.name = cert_param["name"]
        cert_output_response.append(cert_output.model_dump(exclude_none=True))
    return cert_output_response


def update_cert(input_model: InputModel, jwt_token_info: JWTTokenInfo) -> dict:
    """
    Update the certificate and the statefile with the new cert ids.
    Compare the statefile before and after the update and remove the certs that are not in use.

    Parameters:
    input_model: InputModel: input model from main function
    jwt_token_info: JWTTokenInfo: JWT token info with GitHub details

    Returns:
    dict: response

    Raises:
    CertificateServiceException: if there is an error processing the certificate
    """
    try:
        cwd = wd.create_dir()
        if cwd is None:
            raise exceptions.CertificateServiceException(
                "Failed to create working directory"
            )
        cert_parameters = load_cert_parameters(input_model, jwt_token_info, cwd)
        logger.info("Formatted CERT params %s", cert_parameters)
        token_store, cloudflare_scoped_token = cloudflare_token_service.set_cloudflare_scoped_token(input_model)
        zone_id = helpers.get_zone_id(input_model.fqdn, cloudflare_scoped_token)
        cert_ids_before_update = get_cert_tf_state(cwd, input_model, "cert_ids")
        cert_output_response = process_cert_update(cert_parameters, input_model, cloudflare_scoped_token)
        if (
            "priority_enabled" in cert_parameters
            and cert_parameters["priority_enabled"]
        ):
            cert_output_response = process_cert_priority(
                cert_parameters, cert_output_response, cloudflare_scoped_token, zone_id
            )
        disable_universal_ssl(zone_id, cloudflare_scoped_token)
        logger.info("Terraform output type : %s", cert_output_response)
        cert_ids_to_update = {}
        for cert_output in cert_output_response:
            cert_ids_to_update[cert_output["name"]] = cert_output["cert_pack_id"]
        remove_cert(
            cloudflare_scoped_token,
            zone_id,
            cert_ids_before_update,
            cert_ids_to_update,
        )
        tf_vars_json = json.dumps({"cert_details": cert_output_response}, indent=2)
        with open(
            f"{cwd}/terraform.tfvars.json", "w", encoding="utf-8"
        ) as tf_vars_file:
            tf_vars_file.write(tf_vars_json)
        terraform_service.run(input_model, cwd)
        logger.info("cert_ids_to_update: %s", cert_ids_to_update)
    except Exception as e:
        logger.error("Error processing certificate: %s", e)
        raise exceptions.CertificateServiceException(
            f"Error processing certificate: {e}"
        ) from e
    finally:
        try:
            if token_store:
                cf_initial_api_token = helpers.check_initial_token(input_model.environment)
                cloudflare_token_service.delete_all_tokens(
                    cf_initial_api_token, token_store
                )
        except Exception as e:
            logger.error("Error deleting the token: %s", e)
        try:
            if cwd:
                wd.delete_dir(cwd)
        except Exception as e:
            logger.error("Error deleting the working directory: %s", e)
    return cert_output_response


def process_cert_update(cert_parameters: dict, input_model: InputModel, cloudflare_scoped_token: str) -> list:
    """
    Process the certificate update.
    Check if the CSR exists in the account by comparing the name and SANs.
    If the CSR does not exist,
        Generate a new CSR
        Create a new certificate by calling Venafi
        Upload the certificate to Cloudflare.
    If the CSR exists, check if the certificate exists for the CSR in CF.
    If the certificate does not exist,
        Create a new certificate by calling Venafi using CSR id as cert name.
        Upload the certificate to Cloudflare.
    If the certificate exists, do nothing.


    Parameters:
    cert_parameters: list: certificate parameters
    input_model: InputModel: input model

    Returns:
    list: certificate output response as dict
    """
    cert_output_response = []
    env = input_model.environment.value
    zone_id = helpers.get_zone_id(input_model.fqdn, cloudflare_scoped_token)
    all_account_csrs = list_cf_account_csr(
        cloudflare_scoped_token, input_model.account_id
    )
    all_zone_certs = list_cf_zone_certificates(cloudflare_scoped_token, zone_id)
    for cert_param in cert_parameters["certs"]:
        cert_output = CertOutputModel()
        exist_csr = get_cf_account_csr_by_input(
            cert_param,
            all_account_csrs,
        )
        if not exist_csr:
            logger.info("CSR not found. Generating new CSR")
            csr_result = generate_cf_account_csr(
                cloudflare_scoped_token,
                input_model.account_id,
                cert_param,
            )
            cert_result = create_cert(
                cloudflare_scoped_token, env, zone_id, csr_result, cert_param
            )
            cert_output.expires_on = cert_result["expires_on"]
            cert_output.cert_pack_id = cert_result["id"]
        else:
            logger.info("CSR found. Using the existing CSR %s", exist_csr["id"])
            csr_result = exist_csr
            cert_result = get_cf_zone_cert_by_csr(
                csr_result["id"],
                all_zone_certs,
            )
            if not cert_result:
                logger.info("Cert does not exist for the CSR %s", csr_result["id"])
                cert_result = create_cert(
                    cloudflare_scoped_token,
                    env,
                    zone_id,
                    csr_result,
                    cert_param,
                )
                cert_output.expires_on = cert_result["expires_on"]
                cert_output.cert_pack_id = cert_result["id"]
            else:
                cert_output.expires_on = cert_result["expires_on"]
                cert_output.cert_pack_id = cert_result["cert_pack_id"]
                logger.info("Certificate is valid.")
        cert_output.csr_id = csr_result["id"]
        cert_output.common_name = csr_result["common_name"]
        cert_output.sans = csr_result["sans"]
        cert_output.name = cert_param["name"]
        cert_output_response.append(cert_output.model_dump(exclude_none=True))
    return cert_output_response


def load_cert_parameters(
    input_model: InputModel, jwt_token_info: JWTTokenInfo, cwd: str
) -> dict:
    """
    Load the certificate parameters from the Github service

    Parameters:
    input_model: InputModel: input model
    jwt_token_info: JWTTokenInfo: JWT token info
    cwd: str: current working directory

    Returns:
    dict: certificate parameters

    Raises:
    CertificateServiceException: if there is an error running the Github service
    """
    try:
        github_service.main(jwt_token_info, input_model, cwd)
    except exceptions.GithubServiceException as e:
        logger.error("Error running Github service: %s", e)
        raise exceptions.CertificateServiceException(e) from e
    except Exception as e:
        logger.error("Error running Github service: %s", e)
        raise exceptions.CertificateServiceException(e) from e
    with open(
        f"{cwd}/cert_parameters.yml", "r", encoding="utf-8"
    ) as cert_parameters_yml:
        cert_parameters = yaml.safe_load(cert_parameters_yml.read())
    cert_parameters = format_cert_input(cert_parameters, input_model.environment.value)
    return cert_parameters


def get_cert_tf_state(
    working_directory: str, input_model: InputModel, output_name: str
) -> dict:
    """
    Get the certificate details from the Terraform state file using `terraform output -json`
    Run Terraform init before running the output command.

    Parameters:
    working_directory: str: working directory
    input_model: InputModel: input model
    output_name: str: output name

    Returns:
    dict: certificate details

    Raises:
    exceptions.TerraformServiceOperationException: if there is an error running Terraform
    """
    codebase_path = f"cf/terraform/{input_model.config_type.lower()}"
    wd.copy_tf_files(codebase_path, working_directory)
    init_returncode, init_stdout, init_stderr = terraform_service.terraform_init(
        working_directory, input_model.fqdn, input_model.config_type
    )
    if init_returncode != 0:
        logger.error("Error initializing Terraform: %s", init_stdout)
        raise exceptions.CertificateServiceException(
            f"Error initializing Terraform: {init_stderr}"
        )
    logger.info("Terraform output: %s", init_stdout)
    out_returncode, out_stdout, out_stderr = terraform_service.terraform_output(
        working_directory, output_name, "-json"
    )
    logger.info("Terraform state output: %s", out_stdout)
    if out_returncode != 0:
        logger.error("Terraform output STDOUT : %s, STDERR: %s", out_stdout, out_stderr)
        return {}
    terraform_state_output = json.loads(out_stdout)
    return terraform_state_output


def remove_cert(
    cf_token: str,
    zone_id: str,
    cert_ids_before_update: dict,
    cert_ids_to_update: dict,
) -> bool:
    """
    Remove the old certificates that are not in use after the update

    Parameters:
    cf_token: str: Cloudflare API token
    zone_id: str: zone ID
    cert_ids_before_update: dict: certificate IDs before the update
    cert_ids_to_update: dict: certificate IDs after the update

    Returns:
    NA
    """
    if cert_ids_before_update:
        for key, cert_pack_id in cert_ids_before_update.items():
            if cert_pack_id not in cert_ids_to_update.values():
                if get_cf_zone_cert_by_id(cf_token, zone_id, cert_pack_id):
                    remove_cf_zone_certificate(cf_token, zone_id, cert_pack_id)
                    logger.info(
                        "Removed old certificate %s with id %s", key, cert_pack_id
                    )
                else:
                    logger.info(
                        "Certificate %s with id %s is not available in the zone",
                        key,
                        cert_pack_id,
                    )
            else:
                logger.info(
                    "Certificate %s with id %s is still in use", key, cert_pack_id
                )
    else:
        logger.info("No old certificates to remove")


def remove_cert_plan(cert_ids_from_state: dict, cert_output_response: dict) -> dict:
    """
    Create a plan for cert removal if the cert is not in the yaml but in the state file

    Parameters:
    cert_ids_from_state: dict: certificate IDs from the state file
    cert_output_response: dict: certificate output response

    Returns:
    dict: certificate output response
    """
    logger.info("Remove Plan")
    for cert in cert_ids_from_state.keys():
        logger.info("Cert: %s", cert)
        if cert not in [c["name"] for c in cert_output_response]:
            logger.info("Cert not in output: %s", cert)
            cert_output_response.append(
                {
                    "name": cert_ids_from_state[cert]["name"],
                    "csr_id": cert_ids_from_state[cert]["csr_id"],
                    "cert_pack_id": cert_ids_from_state[cert]["cert_pack_id"]
                    + " "
                    + api_constant.TO_BE_REMOVED,
                    "expires_on": cert_ids_from_state[cert]["expires_on"],
                    "common_name": cert_ids_from_state[cert]["common_name"],
                    "sans": cert_ids_from_state[cert]["sans"],
                }
            )
    return cert_output_response


def process_cert_priority(
    cert_parameters: dict, cert_output_response: dict, cf_token: str, zone_id: str
) -> list:
    """
    Get the priority of the certificate in the parameters YAML and create a payload to update the priority with cert id from the cert output response

    Parameters:
    cert_parameters: dict: certificate parameters from YAML
    cert_output_response: dict: certificate output response from CF API
    cf_token: str: token that has permission to edit SSL and Certificates
    zone_id: str: zone ID

    Returns:
    list: certificate output response with priority
    """
    cert_name_priority_map = {}
    logger.info("Prepare priority payload")
    for cert_parameter in cert_parameters["certs"]:
        cert_name_priority_map[cert_parameter["name"]] = cert_parameter["priority"]
    payload = {
        "certificates": [
            {
                "id": cert["cert_pack_id"],
                "priority": cert_name_priority_map[cert["name"]],
            }
            for cert in cert_output_response
        ]
    }
    logger.info("Cert priority payload: %s", payload)
    result = update_cf_zone_cert_priority(cf_token, zone_id, payload)
    cert_id_priority_map = {r["id"]: r["priority"] for r in result}
    logger.info("Cert id priority map: %s", cert_id_priority_map)
    cert_response = [
        {**cert, "priority": cert_id_priority_map.get(cert["cert_pack_id"])}
        for cert in cert_output_response
    ]
    logger.info("cert_response: %s", cert_response)
    return cert_response


def update_cf_zone_cert_priority(
    cf_token: str, zone_id: str, cert_priority_payload: dict
) -> list:
    """
    Update the priority of the certificate in the provided zone_id

    Parameters:
    cf_token: str: token that has permission to edit SSL and Certificates
    zone_id: str: zone ID
    cert_priority_payload: dict: payload to update the priority

    Returns:
    list: updated certificate response with priority

    Raises:
    CertificateServiceCFAPIException: if the API call fails
    """
    logger.info("Updating certificates priority")
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/custom_certificates/prioritize"
    logger.info("Priority payload: %s", cert_priority_payload)
    try:
        response = httpx.put(
            url, json=cert_priority_payload, headers=get_auth_header(cf_token)
        )
        response.raise_for_status()
    except httpx.HTTPError as e:
        raise exceptions.CertificateServiceCFAPIException(
            f"Failed to update certificate priorities: {e}"
        ) from e
    logger.info("Successfully updated all cert priorities")
    response_json = response.json()
    if response.status_code != 200 or "result" not in response_json:
        raise exceptions.CertificateServiceCFAPIException(
            f"Failed to update certificate priorities : {response_json}"
        )
    result = response_json["result"]
    logger.info("Cert priorities update response: %s", result)
    return result


def disable_universal_ssl(zone_id: str, cloudflare_scoped_token: str) -> None:
    """
    Disable Universal SSL for the zone
    """
    logger.info("Disabling Universal SSL for the zone")
    url = f"https://api.cloudflare.com/client/v4/zones/{zone_id}/ssl/universal/settings"
    try:
        res = httpx.patch(
            url,
            headers=get_auth_header(cloudflare_scoped_token),
            json={"enabled": False},
        )
        res.raise_for_status()
    except httpx.HTTPError as e:
        raise exceptions.CertificateServiceCFAPIException(
            f"Failed to disable Universal SSL: {e}"
        ) from e

    logger.info("Universal SSL disabled successfully: %s", res.json())
