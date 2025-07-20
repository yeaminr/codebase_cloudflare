import cloudflare
import pytest

from runner.src.model import InputModel
from runner.src import cloudflare_notification_service, cloudflare_token_service, exceptions, helpers


input_model = InputModel(
    environment="dev", action="apply", config_type="zone", fqdn="fqdn"
)


def test_add_zone_to_all_notifications_in_account(monkeypatch):
    # success scenario
    monkeypatch.setattr(
        cloudflare_token_service, "set_cloudflare_scoped_token",
        lambda x : (["tokenid"], "dummy_token")
    )
    monkeypatch.setattr(helpers, "get_zone_id", lambda x, y: "zone_id")
    monkeypatch.setattr(cloudflare.Cloudflare, "__init__",
                            MockCloudflare.__init__)
    monkeypatch.setattr(
        cloudflare_token_service, "delete_all_tokens", lambda x, y: []
    )
    monkeypatch.setattr(helpers, "check_initial_token", check_initial_token_mock)


    res = cloudflare_notification_service.add_zone_to_all_notifications_in_account(input_model)
    assert res is None

    # error scenario - zone not found
    monkeypatch.setattr(helpers, "get_zone_id", ValueError("Zone not found"))
    with pytest.raises(exceptions.NotificationServiceException):
        cloudflare_notification_service.add_zone_to_all_notifications_in_account(input_model)


class MockCloudflare:
    def __init__(self, api_token):
        self.alerting = Policy

class Filter:
    zones = []

    def to_dict():
        return {"zones": []}

class Alert:
    def __init__(self, name):
        self.name = name
        self.id = "alert_id"
        self.filters = Filter
        self.mechanisms = {}
        self.alert_type = "alert_type"
        self.description = "description"
        self.enabled = True


class Policies:
    def list(account_id):
        return [Alert("Alert1"), Alert("Alert2")]

    def update(policy_id, account_id, filters, mechanisms, alert_type, description, enabled, name):
        return {"status": "success"}

class Policy:
    policies = Policies

def check_initial_token_mock(environment) -> str:
    return "api_token"
