"""
Fast API entry point for the the DHP runner
"""

import re
import os
import logging
from typing import Annotated
from fastapi import FastAPI, HTTPException, Depends, Query, Header
from runner.src import terraform_service
from runner.src import github_service
from runner.src import working_dir as wd
from runner.src.model import EnvironmentModel, InputModel
from runner.src import exceptions
from runner.src import aws_service
from runner.src import auth_service
from runner.src import api_constant
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src import cloudflare_token_service
from runner.src import cert_service

logger = logging.getLogger(__name__)


def custom_headers(x_github_auth_header: str = Header()):
    """
    Custom header dependency to get the x-github-auth header
    """
    return x_github_auth_header


app = FastAPI(root_path="/runner", redoc_url="/redocs")


@app.get("/health")
def health():
    """
    Health check endpoint
    """
    logger.info("Health check endpoint")
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
    response = runner(jwt_token_info=jwt_token_info, input_model=input_model)
    return response


@app.post("/account/{environment}", dependencies=[Depends(custom_headers)])
def update_account(
    environment: EnvironmentModel,
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Update cloudflare account details - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for Account API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="apply", config_type="account"
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
    if not auth_service.verify_repo_action(jwt_token_info.repo_name, fqdn):
        raise HTTPException(
            status_code=403,
            detail="The requesting repo is not authorized to perform action on the given CF zone",
        )
    input_model = InputModel(
        environment=environment, action="plan", config_type="zone", fqdn=fqdn
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
):
    """
    Create/Update cloudflare zone - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for Zone API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    if not auth_service.verify_repo_action(jwt_token_info.repo_name, fqdn):
        raise HTTPException(
            status_code=403,
            detail="The requesting repo is not authorized to perform action on the given CF zone",
        )
    input_model = InputModel(
        environment=environment, action="apply", config_type="zone", fqdn=fqdn
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
    if not auth_service.verify_repo_action(jwt_token_info.repo_name, fqdn):
        raise HTTPException(
            status_code=403,
            detail="The requesting repo is not authorized to perform this cdn action on the given CF zone",
        )
    input_model = InputModel(
        environment=environment, action="plan", config_type="cdn", fqdn=fqdn
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
):
    """
    Update cloudflare CDN config - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for CDN API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    if not auth_service.verify_repo_action(jwt_token_info.repo_name, fqdn):
        raise HTTPException(
            status_code=403,
            detail="The requesting repo is not authorized to perform this CDN action on the given CF zone",
        )
    input_model = InputModel(
        environment=environment, action="apply", config_type="cdn", fqdn=fqdn
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
    if not auth_service.verify_repo_action(jwt_token_info.repo_name, fqdn):
        raise HTTPException(
            status_code=403,
            detail="The requesting repo is not authorized to perform this security action on the given CF zone",
        )

    input_model = InputModel(
        environment=environment, action="plan", config_type="security", fqdn=fqdn
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
):
    """
    Update cloudflare security config - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for Security API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    if not auth_service.verify_repo_action(jwt_token_info.repo_name, fqdn):
        raise HTTPException(
            status_code=403,
            detail="The requesting repo is not authorized to perform this security action on the given CF zone",
        )
    input_model = InputModel(
        environment=environment, action="apply", config_type="security", fqdn=fqdn
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
    if not auth_service.verify_repo_action(jwt_token_info.repo_name, fqdn):
        raise HTTPException(
            status_code=403,
            detail="The requesting repo is not authorized to perform this TLS action on the given CF zone",
        )
    input_model = InputModel(
        environment=environment, action="plan", config_type="tls", fqdn=fqdn
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
):
    """
    Update cloudflare TLS config - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for TLS API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    if not auth_service.verify_repo_action(jwt_token_info.repo_name, fqdn):
        raise HTTPException(
            status_code=403,
            detail="The requesting repo is not authorized to perform this TLS action on the given CF zone",
        )
    input_model = InputModel(
        environment=environment, action="apply", config_type="tls", fqdn=fqdn
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
    dict: Apply response
    """
    logger.info("Runner job started for CERT API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="cert", fqdn=fqdn
    )
    try:
        response = cert_service.plan_cert(
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
):
    """
    Update cloudflare TLS config - apply operation

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Apply response
    """
    logger.info("Runner job started for CERT API - UPDATE - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="apply", config_type="cert", fqdn=fqdn
    )
    try:
        response = cert_service.process_cert(
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


@app.get("/account/{environment}/token", dependencies=[Depends(custom_headers)])
def get_account_token(
    environment: EnvironmentModel,
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Get cloudflare account scoped token

    Parameters:
    environment: EnvironmentModel - environment name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Cloudflare account scoped token
    """
    logger.info("Runner job started for Account Token API - GET - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="account"
    )
    token_store = cloudflare_token_service.set_cloudflare_scoped_token(input_model)
    cloudflare_scoped_token = os.environ.get("CLOUDFLARE_API_TOKEN", None)
    if cloudflare_scoped_token:
        return {"token": cloudflare_scoped_token, "id": token_store[0]}
    raise HTTPException(
        status_code=404, detail="Cloudflare account scoped token not found"
    )


@app.get("/zone/{environment}/token", dependencies=[Depends(custom_headers)])
def get_zone_token(
    environment: EnvironmentModel,
    fqdn: Annotated[
        str | None, Query(pattern=re.compile(api_constant.FQDN_NAME_PATTERN))
    ],
    jwt_token_info: Annotated[JWTTokenInfo, Depends(auth_service.verify_token)],
):
    """
    Get cloudflare zone scoped token

    Parameters:
    environment: EnvironmentModel - environment name
    fqdn: str - fqdn name
    jwt_token_info: JWTTokenInfo (repo_name, org_name, branch_name, authorized)

    Returns:
    dict: Cloudflare zone scoped token
    """
    logger.info("Runner job started for Zone Token API - GET - %s", environment)
    if not jwt_token_info:
        raise HTTPException(status_code=401, detail=api_constant.NOT_AUTHORIZED_ERROR)
    input_model = InputModel(
        environment=environment, action="plan", config_type="zone", fqdn=fqdn
    )
    token_store = cloudflare_token_service.set_cloudflare_scoped_token(input_model)
    cloudflare_scoped_token = os.environ.get("CLOUDFLARE_API_TOKEN", None)
    if cloudflare_scoped_token:
        return {"token": cloudflare_scoped_token, "id": token_store[0]}
    raise HTTPException(
        status_code=404, detail="Cloudflare zone scoped token not found"
    )


def runner(jwt_token_info: JWTTokenInfo, input_model: InputModel) -> dict:
    """
    Runner function to run the Github and Terraform services

    Parameters:
    jwt_token_info: JWTTokenInfo - JWT token information
    environment: EnvironmentModel - environment name
    config_type: str - config type (account, zone, cdn, security, tls)

    Returns:
    dict: Response from the Terraform service
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
    # To update the TXT record for zone creation only. Will be moved to state machine in future
    if input_model.config_type == "zone" and input_model.action == "apply":
        try:
            txt_record_name = f"cloudflare-verify.{input_model.fqdn}"
            # Getting the TXT record value from zone which is configured terraform output as `verification_keys`
            txt_record_value = terraform_service.terraform_output(
                cwd, "verification_keys"
            )
            aws_service.process_txt_record(
                input_model.fqdn, txt_record_name, txt_record_value
            )
        except exceptions.AWSServiceException as e:
            logger.error("Error updating TXT record for zone activation: %s", e)
            raise HTTPException(
                status_code=500,
                detail=f"Error updating TXT record for zone activation: {e}",
            ) from e
        except Exception as e:
            logger.error("Error updating TXT record: %s", e)
            raise HTTPException(
                status_code=500, detail=f"Error updating TXT record: {e}"
            ) from e
    wd.delete_dir(cwd)
    return response
