from datetime import datetime, timedelta
import logging
import requests
import jwt
import yaml
from jwt.algorithms import RSAAlgorithm
from fastapi import HTTPException, Request
from runner.src import api_constant
from runner.src import exceptions
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src import github_service
from runner.src import working_dir as wd

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
        logger.info("Received JWT: %s", jwt_token_full)
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


def is_requesting_repo_authorized_to_action_on_cf_zone(cf_zone_name, working_dir):
    """
    This function comapres the CF zone name 
    with the zone names in the tenant_onboarding_settings.yml file 
    of the selfservice repo.

    Args:
        cf_zone_name (str): zone name where tenant is requesting changes
        working_dir (str): path to dir containing the YAML selfservice file

    Returns:
        return_type: boolean
    """

    with open(f"{working_dir}/{api_constant.TENANT_ONBOARDING_YAML}", "r") as f:
        data = yaml.safe_load(f)
        if (not data['dev_fqdns']):
            data['dev_fqdns'] = []
        if (not data['tst_fqdns']):
            data['tst_fqdns'] = []
        if (not data['stg_fqdns']):
            data['stg_fqdns'] = []

        allowed_fqdns = data["dev_fqdns"] + data["tst_fqdns"] + data["stg_fqdns"] + data["prd_fqdns"]
        if (cf_zone_name in allowed_fqdns):
            logger.info (f"CF zone name {cf_zone_name} exists in {api_constant.TENANT_ONBOARDING_YAML}")
            return True

        logger.info (f"CF zone name {cf_zone_name} doesn't exist in {api_constant.TENANT_ONBOARDING_YAML}")
        return False


def fetch_selfservice_repo_tenants(tenant_repo_name) -> str|None:
    """
    This function fetches the tenant_onboarding_settings.yml file from 
    the corresponding tenant directory of the selfservice repo.

    Args:
        tenant_repo_name (str): name of the tenants github repo

    Returns:
        str | None: name of working dir containing the self service YAML settings file
    """

    cwd = wd.create_dir()
    if cwd is None:
        logger.error ("Failed to create working directory")
        return None
    logger.info(f"Working directory: {cwd}")

    # get tenant name by excluding the first common part of the repo name e.g. first 29 chars of 'groupsec-edgesecurity-tenant-commsec-private'
    tenant_repo_prefix_len = len(api_constant.TENANT_REPO_PREFIX)
    dirname = tenant_repo_name[tenant_repo_prefix_len:]

    selfservice_repo_name = api_constant.SELFSERVICE_REPO_NAME
    repo_path = f"tenants/{dirname}/{api_constant.TENANT_ONBOARDING_YAML}"
    repo_ref = "main"
    download_url = github_service.get_download_url(selfservice_repo_name, repo_path, repo_ref)
    logger.info(f"Download URL: {download_url}")

    try:
        github_service.get_file_content(download_url, cwd)
        logger.info(f"Directory {dirname} exists in selfservice repo. Downloaded tenant_onboarding_settings.yml file")
        return cwd
    except Exception as e:
        logger.error(f"Error in fetching tenant_onboarding_settings.yml file: {e}")
        wd.delete_dir(cwd)
        return None


def verify_repo_action(tenant_repo_name: str, cf_zone_name: str) -> bool:
    """
    This function verifies if the requesting repo is authorized to action on the CF zone.

    Args:
        tenant_repo_name (str): name of tenants github repo
        cf_zone_name (int): CF zone where tenant is trying to perform changes

    Returns:
        boolean: if tenant is authorised to perform changes on the zone
    """
    working_dir = fetch_selfservice_repo_tenants(tenant_repo_name)
    if working_dir is None:
        logger.error("Tenant Directory doesn't exist in selfservice repo")
        return False
    try:
        result = is_requesting_repo_authorized_to_action_on_cf_zone(cf_zone_name, working_dir)
        wd.delete_dir(working_dir)
    except Exception as e:
        logger.error(f"Error in verifying the repo action: {e}")
        wd.delete_dir(working_dir)

    return result
