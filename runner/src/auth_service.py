"""
Module provides functions to verify JWT tokens
and validate repository actions against Cloudflare zones.
"""

from datetime import datetime, timedelta
import logging
import base64
import requests
import jwt
import yaml
from jwt.algorithms import RSAAlgorithm
from fastapi import HTTPException, Request
from runner.src import api_constant
from runner.src import exceptions
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src import github_service
from runner.src.model import InputModel

logger = logging.getLogger(__name__)

jkws_cache = {
    "data": None,
    "expires_at": datetime.now(),
    "retry_count": 0,
}


def fetch_github_jkws() -> dict:
    """
    Fetches the JSON Web Key Set (JKWS) from the GitHub API.

    Returns:
        dict: The JSON Web Key Set (JKWS) as a dictionary.

    Raises:
        exceptions.AuthJKWSFetchException: If the request to fetch the JKWS fails.
    """
    if jkws_cache["data"] and jkws_cache["expires_at"] > datetime.now():
        logger.info("Return JWKS value from cache")
        return jkws_cache["data"]
    response = requests.get(api_constant.GITHUB_JWKS_URL, timeout=10)
    if response.status_code == 200:
        jkws_cache["data"] = response.json()
        jkws_cache["expires_at"] = datetime.now() + timedelta(
            seconds=api_constant.github_jkws_cache_expiry
        )
        logger.info("Return JWKS value from API call")
        return response.json()
    raise exceptions.AuthJKWSFetchException()


def verify_token(req: Request) -> JWTTokenInfo:
    """
    Verifies the JWT token in the request headers and returns the decoded token information.

    Args:
        req (Request): The request object containing the headers.

    Returns:
        JWTTokenInfo: The decoded JWT token information with repository details.

    Raises:
        HTTPException: If the Authorization header is not found or the token is invalid.
    """
    if api_constant.AUTH_HEADER not in req.headers:
        logger.info("Received headers: %s", req.headers)
        raise HTTPException(
            status_code=401, detail=f"Auth header {api_constant.AUTH_HEADER} not found"
        )
    jwt_token_full = req.headers[api_constant.AUTH_HEADER]
    if not jwt_token_full.startswith(api_constant.AUTH_TOKEN_PREFIX):
        logger.info(
            "Received JWT: %s", base64.b64encode(jwt_token_full.encode("UTF-8"))
        )
        raise HTTPException(status_code=401, detail="Not a bearer token")
    jwt_token = jwt_token_full[len(api_constant.AUTH_TOKEN_PREFIX) :]
    try:
        header = jwt.get_unverified_header(jwt_token)
        kid = header.get("kid")
        while True:
            jwks = fetch_github_jkws()
            jwk = next((key for key in jwks["keys"] if key["kid"] == kid), None)
            if jwk:
                jkws_cache["retry_count"] = 0
                break
            if jkws_cache["retry_count"] >= api_constant.GITHUB_JKWS_CACHE_RETRY_COUNT:
                raise HTTPException(
                    status_code=401,
                    detail="JWK Public key not found",
                )
            logger.info(
                "JWKS key not found, retrying to fetch JWKS from api : %s",
                jkws_cache["retry_count"],
            )
            jkws_cache["data"] = None
            jkws_cache["retry_count"] += 1
        public_key = RSAAlgorithm.from_jwk(jwk)
        jwt_payload = jwt.decode(
            jwt_token,
            public_key,
            algorithms=["RS256"],
            issuer=api_constant.OIDC_ISSUER,
            audience=api_constant.OIDC_AUDIENCE,
            leeway=api_constant.OIDC_JWT_LEEWAY,
        )
        jwt_token = JWTTokenInfo(
            authorized=True,
            repo_name=jwt_payload["repository"],
            org_name=jwt_payload["repository_owner"],
            branch_name=jwt_payload["ref"].split("refs/heads/")[-1],
        )
    except Exception as e:
        logger.error("Error in validating the JWT token: %s", e)
        raise HTTPException(
            status_code=401,
            detail=f"Invalid JWT token: {e}",
        ) from e
    return jwt_token


def is_requesting_repo_authorized_to_action_on_cf_zone(
    environment: str, cf_zone_name: str, data: dict
):
    """
    This function comapres the CF zone name
    with the zone names in the tenant_onboarding_settings.yml file
    of the selfservice repo.

    Args:
        environment (str): environment where change is being requested
        cf_zone_name (str): zone name where tenant is requesting changes
        working_dir (str): path to dir containing the YAML selfservice file

    Returns:
        return_type: boolean
    """
    onboarding_yaml = api_constant.TENANT_ONBOARDING_YAML

    allowed_fqdns = data.get(f"{environment}_fqdns", [])
    logger.info("List of allowed FQDNs for requesting tenant: %s", allowed_fqdns)
    if cf_zone_name in allowed_fqdns:
        logger.info("CF zone name %s exists in %s", cf_zone_name, onboarding_yaml)
        return True

    logger.info("CF zone name %s doesn't exist in %s", cf_zone_name, onboarding_yaml)
    return False


def fetch_selfservice_repo_tenants(tenant_repo_name) -> dict | None:
    """
    This function fetches the tenant_onboarding_settings.yml file from
    the corresponding tenant directory of the selfservice repo.

    Args:
        tenant_repo_name (str): name of the tenants github repo

    Returns:
        dict | None: contents  of the tenant_onboarding_settings.yml file or None if not found
    """

    # get tenant name by parsing repo name
    tenant_repo_prefix = api_constant.TENANT_REPO_PREFIX
    if tenant_repo_prefix not in tenant_repo_name:
        logger.error(
            "Invalid tenant repo name %s, must be prefixed with %s",
            tenant_repo_name,
            tenant_repo_prefix,
        )
        return None

    # extract tenant name from repo name
    tenant_name = tenant_repo_name[len(tenant_repo_prefix) :]

    selfservice_repo_name = api_constant.SELFSERVICE_REPO_NAME
    repo_path = f"tenants/{tenant_name}/{api_constant.TENANT_ONBOARDING_YAML}"
    repo_ref = "main"
    download_url = github_service.get_download_url(
        selfservice_repo_name, repo_path, repo_ref
    )
    logger.info("Download URL: %s", download_url)

    try:
        file_content_stream = github_service.get_file_content(download_url)
        file_content = yaml.safe_load(file_content_stream)
        logger.info("Directory %s exists in selfservice repo", tenant_name)
        return file_content
    except exceptions.GithubServiceFileFetchException as e:
        # file not found
        logger.error("Error in fetching tenant_onboarding_settings.yml file: %s", e)
        return None


def verify_token_repo_action(jwt_token_info: JWTTokenInfo) -> bool:
    """
    Check if the requesting repo is authorized to perform actions on the token endpoints
    """
    repo_name = jwt_token_info.repo_name
    if repo_name not in api_constant.AUTHORIZED_TOKEN_REPOS:
        return False
    return True



def verify_repo_action(
    jwt_token_info: JWTTokenInfo,
    input_model: InputModel,
) -> bool:
    """
    This function verifies if the requesting repo is authorized to action on the CF zone.

    Args:
        tenant_repo_name (str): name of tenants github repo
        cf_zone_name (int): CF zone where tenant is trying to perform changes

    Returns:
        boolean: if tenant is authorised to perform changes on the zone
    """
    environment = input_model.environment
    cf_zone_name = input_model.fqdn
    config_type = input_model.config_type
    action = input_model.action
    repo_name = jwt_token_info.repo_name
    branch = jwt_token_info.branch_name
    logger.info(
        "Verifying tenant %s is authorized to update %s in %s",
        repo_name,
        cf_zone_name,
        environment.value,
    )
    if action == "apply" and branch != api_constant.REPO_CONFIG_APPLY_BRANCH:
        logger.error(
            "Branch %s is NOT AUTHORIZED to perform %s actions", branch, action
        )
        return False
    if config_type == "account":
        if repo_name not in api_constant.AUTHORIZED_ACCOUNT_REPOS:
            logger.error(
                "Repo %s is NOT AUTHORIZED to perform %s actions on account config",
                repo_name,
                action,
            )
            return False
        logger.info(
            "Repo %s is AUTHORIZED to perform %s actions on account config",
            repo_name,
            action,
        )
        return True
    try:
        file_content = fetch_selfservice_repo_tenants(repo_name)
    except Exception as e:
        logger.error("Error in fetching selfservice repo tenants: %s", e)
        raise HTTPException(
            status_code=500, detail=f"500 Error: Error verifying repo: {e}"
        ) from e
    if file_content is None:
        logger.error("Tenant Directory doesn't exist in selfservice repo")
        return False
    try:
        return is_requesting_repo_authorized_to_action_on_cf_zone(
            environment.value, cf_zone_name, file_content
        )
    except Exception as e:
        logger.error("Error in verifying the repo action: %s", e)
        raise HTTPException(
            status_code=500, detail=f"500 Error: Error verifying repo: {e}"
        ) from e
