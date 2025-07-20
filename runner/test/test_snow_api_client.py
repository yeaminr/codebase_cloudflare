import os
import httpx
import pytest
from runner.src.snow_api_client import SNOWRestApiClient, get_snow_client
from runner.src import exceptions, api_constant, api_config


def test_snow_rest_api_client_initialization(monkeypatch):
    """
    Test the initialization of the SNOWRestApiClient to ensure it sets up correctly.
    """
    # Test that the SNOWRestApiClient can be initialized without errors
    try:
        snow_client = SNOWRestApiClient(
            host_url="https://your_instance.service-now.com",
            username="username",
            password="password",
        )
        assert snow_client.host_url == "https://your_instance.service-now.com"
    except Exception as e:
        pytest.fail(f"SNOWRestApiClient initialization failed: {e}")

    # Test that the client raises an error if the host URL is not provided
    monkeypatch.setattr(api_config.api_config, "SNOW_HOST_URL", None)
    with pytest.raises(exceptions.SnowServiceValueError):
        snow_client = SNOWRestApiClient()


def test_rest_api_call(monkeypatch):
    """
    Test the REST API call to ensure it returns a valid response.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )
    
    # Success case - Valid GET request
    monkeypatch.setattr(
        httpx,
        "get",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"message": "Success"},
            request=httpx.Request("GET", "test"),
        ),
    )
    response = snow_client.rest_api_call(
        url="https://your_instance.service-now.com",
        method="GET",
    )
    assert response.json() == {"message": "Success"}

    # Success case - Valid POST request
    monkeypatch.setattr(
        httpx,
        "post",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"message": "Success"},
            request=httpx.Request("POST", "test"),
        ),
    )
    response = snow_client.rest_api_call(
        url="https://your_instance.service-now.com",
        method="POST",
    )
    assert response.json() == {"message": "Success"}

    # Success case - Valid PATCH request
    monkeypatch.setattr(
        httpx,
        "patch",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"message": "Success"},
            request=httpx.Request("PATCH", "test"),
        ),
    )
    response = snow_client.rest_api_call(
        url="https://your_instance.service-now.com",
        method="PATCH",
    )
    assert response.json() == {"message": "Success"}

    # Success case - Valid PUT request
    monkeypatch.setattr(
        httpx,
        "put",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"message": "Success"},
            request=httpx.Request("PUT", "test"),
        ),
    )
    response = snow_client.rest_api_call(
        url="https://your_instance.service-now.com",
        method="PUT",
    )
    assert response.json() == {"message": "Success"}

    # Error case: Invalid method
    with pytest.raises(exceptions.SnowServiceException):
        snow_client.rest_api_call(
            url="https://your_instance.service-now.com",
            method="INVALID_METHOD",
        )

    # Error case: httpx raises an exception
    monkeypatch.setattr(
        httpx,
        "get",
        lambda *args, **kwargs: httpx.Response(
            500,
            request=httpx.Request("GET", "test"),
        ),
    )
    with pytest.raises(exceptions.SnowServiceAPICallException):
        snow_client.rest_api_call(
            url="https://your_instance.service-now.com",
            method="GET",
        )


def test_create_change_request(monkeypatch):
    """
    Test the create_change_request method to ensure it creates a change request successfully.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={
                "result": {
                    "number": {"display_value": "CHG00012345"},
                    "sys_id": "12345",
                }
            },
            request=httpx.Request("POST", "test"),
        ),
    )

    # Success case
    change_request = snow_client.create_change_request(
        payload={"dummy_key": "dummy_value"}
    )
    assert change_request["result"]["sys_id"] == "12345"

    # Error case: Invalid payload
    with pytest.raises(exceptions.SnowServiceValueError):
        snow_client.create_change_request(payload=None)

    # Error case: API call fails
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            500,
            request=httpx.Request("POST", "test"),
        ),
    )
    with pytest.raises(exceptions.SnowServiceAPICallException):
        snow_client.create_change_request(payload={"dummy_key": "dummy_value"})


def test_create_change_task(monkeypatch):
    """
    Test the create_change_task method to ensure it creates a change task successfully.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={
                "result": {
                    "number": {"display_value": "CTASK00012345"},
                    "sys_id": "12345",
                }
            },
            request=httpx.Request("POST", "test"),
        ),
    )

    # Success case
    change_task = snow_client.create_change_task(
        "change_id", payload={"dummy_key": "dummy_value"}
    )
    assert change_task["result"]["sys_id"] == "12345"

    # Error case: Invalid payload
    with pytest.raises(exceptions.SnowServiceValueError):
        snow_client.create_change_task(None, payload=None)

    # Error case: API call fails
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            500,
            request=httpx.Request("POST", "test"),
        ),
    )
    with pytest.raises(exceptions.SnowServiceAPICallException):
        snow_client.create_change_task(
            "change_id", payload={"dummy_key": "dummy_value"}
        )


def test_patch_change_request(monkeypatch):
    """
    Test the patch_change_request method to ensure it updates a change request successfully.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={
                "result": {"number": {"display_value": "CHG12345"}, "sys_id": "12345"}
            },
            request=httpx.Request("PATCH", "test"),
        ),
    )

    # Success case
    updated_change_request = snow_client.patch_change_request(
        "change_id", payload={"dummy_key": "dummy_value"}
    )
    assert updated_change_request["result"]["sys_id"] == "12345"

    # Error case: Invalid payload
    with pytest.raises(exceptions.SnowServiceValueError):
        snow_client.patch_change_request("change_id", payload=None)

    # Error case: API call fails
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            500,
            request=httpx.Request("PATCH", "test"),
        ),
    )
    with pytest.raises(exceptions.SnowServiceAPICallException):
        snow_client.patch_change_request(
            "change_id", payload={"dummy_key": "dummy_value"}
        )


def test_patch_change_task(monkeypatch):
    """
    Test the patch_change_task method to ensure it updates a change task successfully.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={
                "result": {"number": {"display_value": "CTASK12345"}, "sys_id": "12345"}
            },
            request=httpx.Request("PATCH", "test"),
        ),
    )

    # Success case
    updated_change_task = snow_client.patch_change_task(
        "task_id", payload={"state": "3"}
    )
    assert updated_change_task["result"]["sys_id"] == "12345"

    # Error case: Invalid payload
    with pytest.raises(exceptions.SnowServiceValueError):
        snow_client.patch_change_task("task_id", payload=None)

    # Error case: API call fails
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            500,
            request=httpx.Request("PATCH", "test"),
        ),
    )
    with pytest.raises(exceptions.SnowServiceAPICallException):
        snow_client.patch_change_task("task_id", payload={"state": "3"})


def test_prepare_patch_change_task_payload():
    """
    Test the prepare_patch_change_task_payload method to ensure it prepares the payload correctly.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )
    # Success state payload
    assert snow_client.prepare_patch_change_task_payload(
        {
            "state": "3",
        }
    ) == {
        "state": "3",
        "close_code": "successful",
        "close_notes": "Change task closed successfully.",
    }
    # Cancelled state payload
    assert snow_client.prepare_patch_change_task_payload(
        {
            "state": "4",
        }
    ) == {
        "state": "4",
        "close_code": "canceled",
        "close_notes": "Change task canceled.",
    }
    # In progess state payload
    assert snow_client.prepare_patch_change_task_payload(
        {
            "state": "2",
        }
    ) == {"state": "2", "work_notes": "Change task is in progress."}
    # Open state payload
    assert snow_client.prepare_patch_change_task_payload(
        {
            "state": "1",
        }
    ) == {"state": "1", "work_notes": "Change moved to open state."}
    # Pending state payload
    assert snow_client.prepare_patch_change_task_payload(
        {
            "state": "-5",
        }
    ) == {"state": "-5"}
    # Invalid state payload
    with pytest.raises(exceptions.SnowServiceValueError):
        snow_client.prepare_patch_change_task_payload(
            {
                "state": "invalid_state",
            }
        )
    # Invalid payload
    with pytest.raises(exceptions.SnowServiceValueError):
        snow_client.prepare_patch_change_task_payload(None)


def test_get_change_next_state(monkeypatch):
    """
    Test the get_change_next_state method to ensure it returns the correct next state.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    next_state_json = {
        "result": {
            "available_states": ["3", "0"],
            "state_transitions": [],
            "state_label": {"3": "Closed", "0": "Review"},
        }
    }
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            200,
            json=next_state_json,
            request=httpx.Request("PATCH", "test"),
        ),
    )
    next_state = snow_client.get_change_next_state("change_id")
    assert next_state == next_state_json

    # Error case: API call fails
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            500,
            request=httpx.Request("PATCH", "test"),
        ),
    )
    # with pytest.raises(exceptions.SnowServiceAPICallException):
    assert not snow_client.get_change_next_state("change_id")


def test_get_all_change_task_by_change_request(monkeypatch):
    """
    Test the get_all_change_task_by_change_request method to ensure it returns all change tasks for a given change request.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    mock_response = {
        "result": [
            {"sys_id": "task1", "number": {"display_value": "CTASK0001"}},
            {"sys_id": "task2", "number": {"display_value": "CTASK0002"}},
        ]
    }
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            200,
            json=mock_response,
            request=httpx.Request("GET", "test"),
        ),
    )

    # Success case
    tasks = snow_client.get_all_change_task_by_change_request("change_id")
    assert len(tasks["result"]) == 2
    assert tasks["result"][0]["sys_id"] == "task1"
    assert tasks["result"][1]["sys_id"] == "task2"

    # Error case: API call fails
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            500,
            request=httpx.Request("GET", "test"),
        ),
    )
    with pytest.raises(exceptions.SnowServiceAPICallException):
        snow_client.get_all_change_task_by_change_request("change_id")


def test_get_table_dynamic_list(monkeypatch):
    """
    Test the get_dynamic_list method to ensure it retrieves a dynamic list from ServiceNow.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    mock_response = {
        "result": [
            {"value": "item1", "label": "Item 1"},
            {"value": "item2", "label": "Item 2"},
        ]
    }
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            200,
            json=mock_response,
            request=httpx.Request("GET", "test"),
        ),
    )

    # Success case
    dynamic_list = snow_client.get_table_dynamic_list("table_url")
    assert len(dynamic_list) == 2
    assert dynamic_list[0]["value"] == "item1"
    assert dynamic_list[1]["value"] == "item2"

    # Empty response case
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"result": []},
            request=httpx.Request("GET", "test"),
        ),
    )
    with pytest.raises(exceptions.SnowServiceNotFoundError):
        snow_client.get_table_dynamic_list("table_url")

    # Error case: API call fails
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            500,
            request=httpx.Request("GET", "test"),
        ),
    )
    with pytest.raises(exceptions.SnowServiceAPICallException):
        snow_client.get_table_dynamic_list("table_url")


def test_get_change_by_number(monkeypatch):
    """
    Test the get_change_by_number method to ensure it retrieves a change request by its number.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    mock_response = {
        "result": [
            {
                "number": {"display_value": "CHG00012345"},
                "sys_id": "12345",
            }
        ]
    }

    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            200,
            json=mock_response,
            request=httpx.Request("GET", "test"),
        ),
    )

    # Success case
    change_response = snow_client.get_change_by_number("CHG00012345")
    assert change_response == mock_response["result"][0]

    # Empty response case
    monkeypatch.setattr(
        SNOWRestApiClient,
        "rest_api_call",
        lambda *args, **kwargs: httpx.Response(
            200,
            json={"result": []},
            request=httpx.Request("GET", "test"),
        ),
    )
    with pytest.raises(exceptions.SnowServiceNotFoundError):
        snow_client.get_change_by_number("CHG00012345")


def test_get_user_by_name(monkeypatch):
    """
    Test the get_user_by_name method to ensure it retrieves a user by their name.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    mock_response = [
        {
            "user_name": {"display_value": "test_user"},
            "sys_id": "12345",
        }
    ]
    monkeypatch.setattr(
        SNOWRestApiClient,
        "get_table_dynamic_list",
        lambda *args, **kwargs: mock_response,
    )

    # Success case
    user_response = snow_client.get_user_by_name("test_user")
    assert user_response == mock_response[0]

    # Empty response case
    monkeypatch.setattr(
        SNOWRestApiClient,
        "get_table_dynamic_list",
        lambda *args, **kwargs: [],
    )
    with pytest.raises(exceptions.SnowServiceNotFoundError):
        snow_client.get_user_by_name("test_user")


def test_get_service_offering_by_name(monkeypatch):
    """
    Test the get_service_offering_by_name method to ensure it retrieves a service offering by its name.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    mock_response = [
        {
            "name": {"display_value": "Test Service Offering"},
            "sys_id": "12345",
        }
    ]
    monkeypatch.setattr(
        SNOWRestApiClient,
        "get_table_dynamic_list",
        lambda *args, **kwargs: mock_response,
    )

    # Success case
    service_offering_response = snow_client.get_service_offering_by_name(
        "Test Service Offering"
    )
    assert service_offering_response == mock_response[0]

    # Empty response case
    monkeypatch.setattr(
        SNOWRestApiClient,
        "get_table_dynamic_list",
        lambda *args, **kwargs: [],
    )
    with pytest.raises(exceptions.SnowServiceNotFoundError):
        snow_client.get_service_offering_by_name("Test Service Offering")


def test_get_ci_by_name(monkeypatch):
    """
    Test the get_ci_by_name method to ensure it retrieves a configuration item by its name.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    mock_response = [
        {
            "name": {"display_value": "Test CI"},
            "sys_id": "12345",
        }
    ]
    monkeypatch.setattr(
        SNOWRestApiClient,
        "get_table_dynamic_list",
        lambda *args, **kwargs: mock_response,
    )

    # Success case
    ci_response = snow_client.get_ci_by_name("Test CI")
    assert ci_response == mock_response[0]

    # Empty response case
    monkeypatch.setattr(
        SNOWRestApiClient,
        "get_table_dynamic_list",
        lambda *args, **kwargs: [],
    )
    with pytest.raises(exceptions.SnowServiceNotFoundError):
        snow_client.get_ci_by_name("Test CI")


def test_get_group_by_name(monkeypatch):
    """
    Test the get_group_by_name method to ensure it retrieves a group by its name.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )

    # Mock the response for the API call
    mock_response = [
        {
            "name": {"display_value": "Test Group"},
            "sys_id": "12345",
        }
    ]
    monkeypatch.setattr(
        SNOWRestApiClient,
        "get_table_dynamic_list",
        lambda *args, **kwargs: mock_response,
    )

    # Success case
    group_response = snow_client.get_group_by_name("Test Group")
    assert group_response == mock_response[0]

    # Empty response case
    monkeypatch.setattr(
        SNOWRestApiClient,
        "get_table_dynamic_list",
        lambda *args, **kwargs: [],
    )
    with pytest.raises(exceptions.SnowServiceNotFoundError):
        snow_client.get_group_by_name("Test Group")


def test_prepare_payload(monkeypatch):
    """
    Test the prepare_change_request_payload method to ensure it prepares the payload correctly.
    """
    snow_client = SNOWRestApiClient(
        host_url="https://your_instance.service-now.com",
        username="username",
        password="password",
    )
    monkeypatch.setattr(
        SNOWRestApiClient,
        "get_ci_by_name",
        lambda *args, **kwargs: {"sys_id": "CI12345"},
    )
    monkeypatch.setattr(
        SNOWRestApiClient,
        "get_group_by_name",
        lambda *args, **kwargs: {"sys_id": "GROUP12345"},
    )
    monkeypatch.setattr(
        SNOWRestApiClient,
        "get_user_by_name",
        lambda *args, **kwargs: {"sys_id": "USER12345"},
    )

    # Success case - change request payload
    payload = snow_client.prepare_payload()
    assert payload["cmdb_ci"] == "CI12345"
    assert payload["assignment_group"] == "GROUP12345"
    assert payload["u_peer_review_group"] == "GROUP12345"
    assert payload["assigned_to"] == "USER12345"
    assert payload["start_date"]
    assert payload["end_date"]
    assert "change_task_type" not in payload
    assert "planned_start_date" not in payload
    assert "planned_end_date" not in payload

    # Success case - change task payload
    payload = snow_client.prepare_payload(
        payload_type="change_task", ctask_type="implementation"
    )
    assert payload["change_task_type"] == "implementation"
    assert payload["planned_start_date"]
    assert payload["planned_end_date"]
    assert "start_date" not in payload
    assert "end_date" not in payload

    # Error case - invalid payload type
    with pytest.raises(exceptions.SnowServiceValueError):
        snow_client.prepare_payload(payload_type="invalid_type")

    # Success case - Fields exist in payload
    payload = {
        "cmdb_ci": "CIEXIST",
        "assignment_group": "GROUPEXIST",
        "u_peer_review_group": "GROUPEXIST",
        "assigned_to": "USEREXIST",
    }
    payload = snow_client.prepare_payload(payload=payload)
    assert payload["cmdb_ci"] == "CIEXIST"
    assert payload["assignment_group"] == "GROUPEXIST"
    assert payload["u_peer_review_group"] == "GROUPEXIST"
    assert payload["assigned_to"] == "USEREXIST"


def test_get_snow_client(monkeypatch):
    """
    Test the get_snow_client method to ensure it returns a valid SNOWRestApiClient instance.
    """
    # monkeypatch.setattr(
    #     api_constant, "SNOW_HOST_URL", "https://your_instance.service-now.com"
    # )
    # monkeypatch.setattr(api_constant, "SNOW_USERNAME", "username")
    # monkeypatch.setattr(api_constant, "SNOW_PASSWORD", "password")

    # Get the SNOWRestApiClient instance
    snow_client = get_snow_client()

    # Check if the client is initialized correctly
    assert isinstance(snow_client, SNOWRestApiClient)
