import logging
from pydantic_settings import BaseSettings
from pydantic import ValidationError
from runner.src.exceptions import APIConfigException

logger = logging.getLogger(__name__)


class APIConfig(
    BaseSettings,
):
    """
    Configuration for the API.
    """
    # Mandatory environment variables
    SNOW_HOST_URL: str
    SNOW_USERNAME: str
    SNOW_PASSWORD: str
    SNOW_CF_SERVICE_OFFERING_NAME: str
    SNOW_CF_CMDB_CI_NAME: str

    # Optional environment variables with defaults
    SNOW_AUTHORIZED_REPOS: list[str] = [
        "CBA-Edge-Security-Platform-RSTD/groupsec-edgesecurity-tenant-edge-security",
    ]
    SNOW_SKIP_VERIFY_CHANGE_REQUEST: bool = False # Flag to skip change request verification
    SNOW_SKIP_ENVIRONMENTS: list[str] = ["dev"] # List of environments to skip change request verification
    SNOW_CF_ASSIGNMENT_GROUP: str = "Edge Security - Applications"
    SNOW_CHANGE_VALID_STATES: list[str] = ["Implement"]
    SNOW_CF_ASSIGNED_TO: str = ""
    SNOW_CHANGE_DURATION: str = "24"
    SNOW_CTASK_DURATION: str = "4"
    SNOW_CHANGE_MODEL: str = ""
    SNOW_CHANGE_REQUEST_PAYLOAD_DEFAULT: dict[str, str] = {
        "u_reason_for_change": "request_project",
        "category": "install_new_application_database",
        "u_complexity": "3",
        "u_perceived_risk": "4",
        "impact": "3",
        # "service_offering": None,  # To be set later,
        # "chg_model": None,  # To be set later,
        # "cmdb_ci": None,  # To be set later
        # "assignment_group": None,  # To be set later
        # "u_peer_review_group": None,  # To be set later
        # "assigned_to": None,  # To be set later
        # "start_date": None,  # To be set later
        # "end_date": None,  # To be set later
        "justification": "NEEDS_TO_BE_SET",
        "implementation_plan": "NEEDS_TO_BE_SET",
        "risk_impact_analysis": "NEEDS_TO_BE_SET",
        "u_backout_type": "tested_backout_available",
        "backout_plan": "NEEDS_TO_BE_SET",
        "u_post_deployment_test_type": "TVT_BVT",
        "u_pre_deployment_test_type": "successfully_tested",
        "test_plan": "NEEDS_TO_BE_SET",
        "short_description": "NEEDS_TO_BE_SET",
        "description": "NEEDS_TO_BE_SET",
        "u_sdlc_category": "Change followed SDLC",
    }
    SNOW_CTASK_PAYLOAD_DEFAULT: dict[str, str] = {
        "short_description": "NEEDS_TO_BE_SET",
        "description": "NEEDS_TO_BE_SET",
        # "cmdb_ci": None, # To be set later
        # "assigned_to": None, # To be set later
        # "assignment_group": None, # To be set later
        # "planned_start_date": None, # To be set later
        # "planned_end_date": None, # To be set later
        # "change_task_type": None, # To be set later
    }


try:
    api_config = APIConfig()
except ValidationError as e:
    for field in e.errors():
        logger.error(
            "Validation error in API configuration: %s - %s",
            field["loc"],
            field["msg"],
        )
    logger.error("Please check your environment variables and configuration.")
    raise APIConfigException from e
logger.info("API configuration loaded successfully.")
