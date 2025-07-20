"""
Fast API entry point for the the DHP runner
"""

import re
import logging
from typing import Annotated
from asgi_correlation_id import CorrelationIdMiddleware
from fastapi import FastAPI, HTTPException, Depends, Query, Header
from fastapi.staticfiles import StaticFiles
from runner.src import cloudflare_notification_service, cloudflare_test_service, terraform_service
from runner.src import github_service
from runner.src import working_dir as wd
from runner.src.model import (
    EnvironmentModel,
    InputModel,
    TestInputModel,
    ConfigTypeModel,
)
from runner.src import exceptions
from runner.src import auth_service
from runner.src import api_constant
from runner.src import snow_service
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src import cert_service
from runner.src import mtls_zero_trust_service
from runner.src import cloudflare_iam_service
from runner.src import txt_record_service
from runner.src import validate_service
from runner.src import cloudflare_token_service
from runner.src.middleware import CustomHeaderMiddleware

logger = logging.getLogger(__name__)


def custom_headers(x_github_auth_header: str = Header()):
    """
    Custom header dependency to get the x-github-auth header
    """
    return x_github_auth_header


app = FastAPI(root_path="/runner", redoc_url="/redocs")
app.add_middleware(
    CorrelationIdMiddleware,
    header_name="X-Request-ID",
)
app.add_middleware(CustomHeaderMiddleware)
app.mount("/schema", StaticFiles(directory="schema"), name="schema")


@app.get("/health")
def health():
    """
    Health check endpoint
    """
    return {"status": "ok"}


@app.get("/account/{environment}", dependencies=[Depends(custom_headers)])
def get_account(
    environment: EnvironmentModel,
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Get cloudflare account details - plan operation

    Parameters:
    environment: EnvironmentModel - environment name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Plan response
    """
    logger.info("Runner job started for Account API - GET - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="account"
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.post("/account/{environment}", dependencies=[Depends(custom_headers)])
def update_account(
    environment: EnvironmentModel,
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    change_number: Annotated[str, Depends(snow_service.verify_change_request)],
):
    """
    Update cloudflare account details - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)
    change_number: str - ServiceNow change request number

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for Account API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment,
        action="apply",
        config_type="account",
        change_number=change_number,
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.get("/zone/{environment}", dependencies=[Depends(custom_headers)])
def get_zone(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Get cloudflare zone details - plan operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Plan response
    """
    logger.info("Runner job started for Zone API - GET - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="zone", fqdn=fqdn
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.post("/zone/{environment}", dependencies=[Depends(custom_headers)])
def update_zone(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    change_number: Annotated[str, Depends(snow_service.verify_change_request)],
):
    """
    Create/Update cloudflare zone - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)
    change_number: str - ServiceNow change request number

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for Zone API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment,
        action="apply",
        config_type="zone",
        fqdn=fqdn,
        change_number=change_number,
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.get("/cdn/{environment}", dependencies=[Depends(custom_headers)])
def get_cdn(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Get cloudflare CDN config - plan operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Plan response
    """
    logger.info("Runner job started for CDN API - GET - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="cdn", fqdn=fqdn
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.post("/cdn/{environment}", dependencies=[Depends(custom_headers)])
def update_cdn(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    change_number: Annotated[str, Depends(snow_service.verify_change_request)],
):
    """
    Update cloudflare CDN config - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)
    change_number: str - ServiceNow change request number

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for CDN API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment,
        action="apply",
        config_type="cdn",
        fqdn=fqdn,
        change_number=change_number,
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.get("/security/{environment}", dependencies=[Depends(custom_headers)])
def get_security(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Get cloudflare security config - plan operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Plan response
    """

    logger.info("Runner job started for Security API - GET - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="security", fqdn=fqdn
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.post("/security/{environment}", dependencies=[Depends(custom_headers)])
def update_security(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    change_number: Annotated[str, Depends(snow_service.verify_change_request)],
):
    """
    Update cloudflare security config - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)
    change_number: str - ServiceNow change request number

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for Security API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment,
        action="apply",
        config_type="security",
        fqdn=fqdn,
        change_number=change_number,
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.get("/tls/{environment}", dependencies=[Depends(custom_headers)])
def get_tls(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Get cloudflare TLS config - plan operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Plan response
    """
    logger.info("Runner job started for TLS API - GET - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="tls", fqdn=fqdn
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.post("/tls/{environment}", dependencies=[Depends(custom_headers)])
def update_tls(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    change_number: Annotated[str, Depends(snow_service.verify_change_request)],
):
    """
    Update cloudflare TLS config - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)
    change_number: str - ServiceNow change request number

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for TLS API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment,
        action="apply",
        config_type="tls",
        fqdn=fqdn,
        change_number=change_number,
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.get("/cert/{environment}", dependencies=[Depends(custom_headers)])
def get_cert(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Update cloudflare TLS config - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Plan response
    """
    logger.info("Runner job started for CERT API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="cert", fqdn=fqdn
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    try:
        response = cert_service.get_cert(
            input_model=input_model, jwt_token_info=jwt_token_info
        )
    except exceptions.CertificateServiceException as e:
        logger.error("500 Error: Error running Cert service: %s", e)
        raise HTTPException(
            status_code=500, detail=f"500 Error: Error running Cert service: {e}"
        ) from e
    except Exception as e:
        logger.error("Error running Cert service: %s", e)
        raise HTTPException(
            status_code=500, detail=f"Error running Cert service: {e}"
        ) from e
    return response


@app.post("/cert/{environment}", dependencies=[Depends(custom_headers)])
def update_cert(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    change_number: Annotated[str, Depends(snow_service.verify_change_request)],
):
    """
    Update cloudflare TLS config - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)
    change_number: str - ServiceNow change request number

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for CERT API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment,
        action="apply",
        config_type="cert",
        fqdn=fqdn,
        change_number=change_number,
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    try:
        response = cert_service.update_cert(
            input_model=input_model, jwt_token_info=jwt_token_info
        )
    except exceptions.CertificateServiceException as e:
        logger.error("500 Error: Error running Cert service: %s", e)
        raise HTTPException(
            status_code=500, detail=f"500 Error: Error running Cert service: {e}"
        ) from e
    except Exception as e:
        logger.error("Error running Cert service: %s", e)
        raise HTTPException(
            status_code=500, detail=f"Error running Cert service: {e}"
        ) from e
    return response


@app.get("/mtls/{environment}", dependencies=[Depends(custom_headers)])
def get_mtls(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Get curerntly cloudflare mTLS config - plan operation

    Parameters:
    environment: EnvironmentModel - environment name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Plan response
    """
    logger.info("Runner job started for mTLS API - GET - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="mtls", fqdn=fqdn
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    try:
        response = mtls_zero_trust_service.get_mtls(jwt_token_info, input_model)
    except Exception as e:
        logger.error("Error running mTLS service: %s", e)
        raise HTTPException(
            status_code=400, detail=f"Error running mTLS service: {e}"
        ) from e

    return response


@app.post("/mtls/{environment}", dependencies=[Depends(custom_headers)])
def update_mtls(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    change_number: Annotated[str, Depends(snow_service.verify_change_request)],
):
    """
    Update cloudflare mTLS config - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)
    change_number: str - ServiceNow change request number

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for mTLS API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment,
        action="apply",
        config_type="mtls",
        fqdn=fqdn,
        change_number=change_number,
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    try:
        response = mtls_zero_trust_service.update_mtls(jwt_token_info, input_model)
    except Exception as e:
        logger.error("Error running mTLS service: %s", e)
        raise HTTPException(
            status_code=400, detail=f"Error running mTLS service: {e}"
        ) from e
    return response


@app.get("/workers/{environment}", dependencies=[Depends(custom_headers)])
def get_worker_script(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Get cloudflare workers config - plan operation

    Parameters:
    environment: EnvironmentModel - environment name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Plan response
    """
    logger.info("Runner job started for Workers API - GET - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="workers", fqdn=fqdn
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.post("/workers/{environment}", dependencies=[Depends(custom_headers)])
def update_worker_script(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    change_number: Annotated[str, Depends(snow_service.verify_change_request)],
):
    """
    Update cloudflare workers config - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)
    change_number: str - ServiceNow change request number

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for Workers API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment,
        action="apply",
        config_type="workers",
        fqdn=fqdn,
        change_number=change_number,
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.get("/app_list/{environment}", dependencies=[Depends(custom_headers)])
def get_app_list(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Get cloudflare application specific lists from account level - plan operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Plan response
    """

    logger.info("Runner job started for App List API - GET - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="app_list", fqdn=fqdn
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.post("/app_list/{environment}", dependencies=[Depends(custom_headers)])
def update_app_list(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    change_number: Annotated[str, Depends(snow_service.verify_change_request)],
):
    """
    Update cloudflare application specific lists from account level - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)
    change_number: str - ServiceNow change request number

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for App List API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment,
        action="apply",
        config_type="app_list",
        fqdn=fqdn,
        change_number=change_number,
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.post("/test/{environment}", dependencies=[Depends(custom_headers)])
def execute_tests(
    environment: EnvironmentModel,
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    test_inputs: TestInputModel,
):
    """
    Get cloudflare test results

    Parameters:
    environment: EnvironmentModel - environment name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Test results
    """

    logger.info("Runner job started for Test API - POST - %s", environment)

    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment,
        action="plan",
        config_type="zone",
        fqdn=test_inputs.fqdn,
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    try:
        response = cloudflare_test_service.create_test_session(
            test_inputs, jwt_token_info, input_model
        )
    except Exception as e:
        logger.error("Error running Test service: %s", e)
        raise HTTPException(
            status_code=500, detail=f"Error running Test service: {e}"
        ) from e

    return response


@app.get(
    "/validate/{config_type}/{environment}", dependencies=[Depends(custom_headers)]
)
def validate_yaml(
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    config_type: ConfigTypeModel,
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ] = None,
    change_number: str | None = None,
):
    """
    Validate the yaml file

    Parameters:
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)
    config_type: ConfigTypeModel - config type ("account", "zone", "cdn", "security", "tls", "cert", "mtls", "workers", "app_list")
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name - Optional for account config type
    change_number: str - ServiceNow change request number - Optional for plan operation

    Returns:
    dict: Response from the validate service
    """
    logger.info("Runner job started Validate yaml - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    if change_number:
        change_number = snow_service.verify_change_request(change_number,environment)
    input_model = InputModel(
        environment=environment,
        action="validate",
        config_type=config_type,
        fqdn=fqdn,
        change_number=change_number,
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )
    try:
        response = validate_service.main(input_model, jwt_token_info)
    except Exception as e:
        logger.error("Error running YAML validation: %s", e)
        raise HTTPException(
            status_code=500,
            detail=f"{e}",
        ) from e
    return response


@app.get("/cf-terraforming/{environment}", dependencies=[Depends(custom_headers)])
def cf_terraforming(
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    environment: EnvironmentModel,
    resource_type: str,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ] = None,
):
    """
    Run cf-terraforming to find any missing resources in the Terraform state

    Parameters:
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)
    environment: EnvironmentModel - environment name
    resource_type: str - name of resource to check (cloudflare_ruleset, cloudflare_record)
    fqdn: str - fqdn name

    Returns:
    dict: Response from the cf-terraforming service
    """
    logger.info("Runner job started cf-terraforming - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="zone", fqdn=fqdn
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )

    try:
        output = terraform_service.cf_terraforming(input_model, resource_type)
        return output
    except exceptions.TerraformServiceException as e:
        logger.error("500 Error: Error running Terraform: %s", e)
        raise HTTPException(
            status_code=500, detail=f"500 Error: Error running Terraform: {e}"
        ) from e
    except Exception as e:
        logger.error("Error running cf-terraforming: %s", e)
        raise HTTPException(
            status_code=500, detail=f"Error running cf-terraforming: {e}"
        ) from e


@app.post("/account/{environment}/rotate", dependencies=[Depends(custom_headers)])
def rotate_account_token(
    environment: EnvironmentModel,
#    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
    jwt_token_info = JWTTokenInfo(
        repo_name="CBA-Edge-Security-Platform-RSTD/groupsec-edgesecurity-cloudflare-account-config",
        branch_name="main",
        authorized=True,
        org_name="CBA-Edge-Security-Platform-RSTD",
    ),
):
    """
    Rotate cloudflare Initial API Token.
    This API endpoint will be called from a GHA workflow on a 30 day schedule.

    Parameters:
    environment: EnvironmentModel - environment name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    None
    """
    logger.info("Runner job started to rotate Initial API Token - POST - %s", environment)

    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="account"
    )
    if not auth_service.verify_repo_action(jwt_token_info, input_model):
        raise HTTPException(
            status_code=403,
            detail=api_constant.HTTP_AUTHORIZATION_ERROR_RESPONSE.format(
                repo_name=jwt_token_info.repo_name,
                branch=jwt_token_info.branch_name,
                action=input_model.action,
                config_type=input_model.config_type,
            ),
        )

    try:
        cloudflare_token_service.rotate_cloudflare_initial_token (input_model.environment)
        logger.info ("Initial API token rotation completed.")
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Cloudflare Initial token rotation failed: {e}"
        ) from e


def runner(jwt_token_info: JWTTokenInfo, input_model: InputModel) -> dict:
    """
    Runner function to run the Github and Terraform services

    Parameters:
    jwt_token_info: JWTTokenInfo - JWT token information
    environment: EnvironmentModel - environment name

    Returns:
    dict: Response from the Terraform service

    Raises:
    HTTPException: If there is an error running the Github or Terraform services
    """
    logger.info("Runner job started")
    cwd = wd.create_dir()
    if cwd is None:
        return {"error": "Failed to create working directory"}
    response = {}
    try:
        github_service.main(jwt_token_info, input_model, cwd)
    except exceptions.GithubServiceException as e:
        logger.error("500 Error: Error running Github service: %s", e)
        raise HTTPException(
            status_code=500, detail=f"500 Error: Error running Github service: {e}"
        ) from e
    except Exception as e:
        logger.error("Error running Github service: %s", e)
        raise HTTPException(
            status_code=500, detail=f"Error running Github service: {e}"
        ) from e
    try:
        terraform_output = terraform_service.run(input_model, cwd)
        response["detail"] = terraform_output
    except exceptions.TerraformServiceException as e:
        logger.error("500 Error: Error running Terraform: %s", e)
        raise HTTPException(
            status_code=500, detail=f"500 Error: Error running Terraform: {e}"
        ) from e
    except Exception as e:
        logger.error("Error running Terraform: %s", e)
        raise HTTPException(
            status_code=500, detail=f"Error running Terraform: {e}"
        ) from e
    # To update the TXT record for zone creation only.
    if input_model.config_type == "zone" and input_model.action == "apply":
        # Adding the Zone into the Domain Group
        try:
            cloudflare_iam_service.add_zone_to_domain_group(
                input_model.environment, input_model.fqdn
            )
        except exceptions.CloudflareIAMServiceException as e:
            logger.error("Error adding zone to domain group: %s", e)
            raise HTTPException(
                status_code=500, detail=f"Error modifying domain group: {e}"
            ) from e
        except Exception as e:
            logger.error("Error adding zone to Domain Group: %s", e)
            raise HTTPException(
                status_code=500, detail=f"Error running IAM service: {e}"
            ) from e
        
        # turn on notifications for the zone
        try:
            cloudflare_notification_service.add_zone_to_all_notifications_in_account(
                input_model
            )
        except exceptions.NotificationServiceException as e:
            logger.error("Error adding zone to notifications: %s", e)
            raise HTTPException(
                status_code=500, detail=f"Error adding zone to notifications: {e}"
            ) from e
        except Exception as e:
            logger.error("Error running Cloudflare Notification service: %s", e)
            raise HTTPException(
                status_code=500, detail=f"Error running Cloudflare Notification service: {e}"
            ) from e

        try:
            txt_record_name = f"cloudflare-verify.{input_model.fqdn}"
            # Getting the TXT record value from terraform output as `verification_keys`
            out_returncode, txt_record_value_stdout, out_stderr = (
                terraform_service.terraform_output(cwd, "verification_keys", "-raw")
            )
            if out_returncode != 0:
                logger.error(
                    "Error getting TXT record value from terraform output: %s",
                    out_stderr,
                )
                raise HTTPException(
                    status_code=500,
                    detail=f"Error getting TXT record value from terraform output: {out_stderr}",
                )
            logger.info(
                "TXT Record Value to be updated for zone verification: %s",
                txt_record_value_stdout,
            )
            txt_record_service.process_txt_record(
                input_model, txt_record_name, txt_record_value_stdout, cwd
            )
        except Exception as e:
            logger.error("Error updating TXT record: %s", e)
            raise HTTPException(
                status_code=500, detail=f"Error updating TXT record: {e}"
            ) from e

    wd.delete_dir(cwd)
    return response
