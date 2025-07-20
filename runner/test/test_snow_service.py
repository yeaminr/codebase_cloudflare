import pytest
from fastapi import HTTPException
from runner.src import (
    api_config,
    snow_api_client,
    snow_service,
)


def test_verify_change_request(monkeypatch):
    """
    Test the verify_change_request function.
    """

    # Success case: Environment is in SNOW_SKIP_ENVIRONMENTS
    assert snow_service.verify_change_request("CHG1234567", "dev") == "CHG1234567"

    # Success case: Change request is valid
    monkeypatch.setattr(
        snow_api_client.SNOWRestApiClient,
        "get_change_by_number",
        lambda self, change_request_number: {
            "cmdb_ci": {"display_value": "Test CI Name"},
            "service_offering": {"display_value": "Test Service Offering"},
            "assignment_group": {"display_value": "Edge Security - Applications"},
            "state": {"display_value": "Implement"},
        },
    )
    assert snow_service.verify_change_request("CHG1234567", "prod") == "CHG1234567"

    # Failure case: Change request not found
    monkeypatch.setattr(
        snow_api_client.SNOWRestApiClient,
        "get_change_by_number",
        lambda self, change_request_number: None,
    )
    with pytest.raises(HTTPException):
        snow_service.verify_change_request("CHG1234567", "prod")

    # Failure case: Change request is invalid - CMDB CI name does not match
    monkeypatch.setattr(
        snow_api_client.SNOWRestApiClient,
        "get_change_by_number",
        lambda self, change_request_number: {
            "cmdb_ci": {"display_value": "Invalid CI Name"},
            "service_offering": {"display_value": "Test Service Offering"},
            "assignment_group": {"display_value": "Edge Security - Applications"},
            "state": {"display_value": "Implement"},
        },
    )
    with pytest.raises(HTTPException):
        snow_service.verify_change_request("CHG1234567", "prod")

    # Failure case: Change request is invalid - Service offering does not match
    monkeypatch.setattr(
        snow_api_client.SNOWRestApiClient,
        "get_change_by_number",
        lambda self, change_request_number: {
            "cmdb_ci": {"display_value": "Test CI Name"},
            "service_offering": {"display_value": "Invalid Service Offering"},
            "assignment_group": {"display_value": "Edge Security - Applications"},
            "state": {"display_value": "Implement"},
        },
    )
    with pytest.raises(HTTPException):
        snow_service.verify_change_request("CHG1234567", "prod")

    # Failure case: Change request is invalid - Assignment group does not match
    monkeypatch.setattr(
        snow_api_client.SNOWRestApiClient,
        "get_change_by_number",
        lambda self, change_request_number: {
            "cmdb_ci": {"display_value": "Test CI Name"},
            "service_offering": {"display_value": "Invalid Service Offering"},
            "assignment_group": {"display_value": "Invalid Assignment Group"},
            "state": {"display_value": "Implement"},
        },
    )
    with pytest.raises(HTTPException):
        snow_service.verify_change_request("CHG1234567", "prod")

    # Failure case: Change request is invalid - State is not Implement
    monkeypatch.setattr(
        snow_api_client.SNOWRestApiClient,
        "get_change_by_number",
        lambda self, change_request_number: {
            "cmdb_ci": {"display_value": "Test CI Name"},
            "service_offering": {"display_value": "Test Service Offering"},
            "assignment_group": {"display_value": "Edge Security - Applications"},
            "state": {"display_value": "New"},
        },
    )
    with pytest.raises(HTTPException):
        snow_service.verify_change_request("CHG1234567", "prod")

    # Success case: SNOW_SKIP_VERIFY_CHANGE_REQUEST is True
    api_config.api_config.__dict__.update({"SNOW_SKIP_VERIFY_CHANGE_REQUEST": True})
    assert snow_service.verify_change_request("CHG1234567", "prod") == "CHG1234567"
