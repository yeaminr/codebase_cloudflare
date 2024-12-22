import pytest
from runner.src import aws_service
from runner.src import exceptions


# Tests
def test_change_resource_record_sets(monkeypatch) -> None:
    # Success case - Added try except block to catch any exceptions during failure
    monkeypatch.setattr(
        aws_service.dev_client,
        "change_resource_record_sets",
        aws_change_resource_record_sets_mock,
    )
    assert aws_service.change_resource_record_sets(
        env="dev",
        hosted_zone_id="123456789",
        record_name="example.cba.com.au",
        record_value="test",
        record_type="TXT",
        ttl=300,
    )
    # Empty response
    monkeypatch.setattr(
        aws_service.prod_client,
        "change_resource_record_sets",
        aws_change_resource_record_sets_mock,
    )
    assert not aws_service.change_resource_record_sets(
        env="prod",
        hosted_zone_id="empty",
        record_name="example.cba.com.au",
        record_value="test",
        record_type="TXT",
        ttl=300,
    )
    # Status code not 200
    monkeypatch.setattr(
        aws_service.dev_client,
        "change_resource_record_sets",
        aws_change_resource_record_sets_mock,
    )
    assert not aws_service.change_resource_record_sets(
        env="dev",
        hosted_zone_id="status_code_not_200",
        record_name="example.cba.com.au",
        record_value="test",
        record_type="TXT",
        ttl=300,
    )
    # Exception
    monkeypatch.setattr(
        aws_service.dev_client,
        "change_resource_record_sets",
        aws_change_resource_record_sets_mock,
    )
    with pytest.raises(exceptions.AWSServiceRoute53ChangeResourceRecordSetsException):
        aws_service.change_resource_record_sets(
            env="dev",
            hosted_zone_id="exception",
            record_name="example.cba.com.au",
            record_value="test",
            record_type="TXT",
            ttl=300,
        )


def test_get_hosted_zone_id_by_domain(monkeypatch) -> None:
    # Correct domain name
    monkeypatch.setattr(
        aws_service.prod_client,
        "list_hosted_zones_by_name",
        aws_list_hosted_zones_by_name_mock,
    )
    assert (
        aws_service.get_hosted_zone_id_by_domain("example.cba.com.au", "prod")
        == "/hostedzone/123456789"
    )
    # Incorrect domain name
    monkeypatch.setattr(
        aws_service.dev_client,
        "list_hosted_zones_by_name",
        aws_list_hosted_zones_by_name_mock,
    )
    assert aws_service.get_hosted_zone_id_by_domain("example.cba.com.aa", "dev") == None
    # Empty response
    monkeypatch.setattr(
        aws_service.dev_client,
        "list_hosted_zones_by_name",
        aws_list_hosted_zones_by_name_mock,
    )
    assert aws_service.get_hosted_zone_id_by_domain("", "dev") == None


def test_check_record_exist(monkeypatch) -> None:
    # Success case
    monkeypatch.setattr(
        aws_service.prod_client,
        "list_resource_record_sets",
        aws_list_resource_record_sets_mock,
    )
    assert aws_service.check_record_exist(
        hosted_zone_id="123456789",
        record_name="example.cba.com.au",
        record_type="TXT",
        env="prod",
    )
    # Record not found
    monkeypatch.setattr(
        aws_service.dev_client,
        "list_resource_record_sets",
        aws_list_resource_record_sets_mock,
    )
    assert not (
        aws_service.check_record_exist(
            hosted_zone_id="not_found",
            record_name="example.cba.com.au",
            record_type="TXT",
            env="dev",
        )
    )
    # Invalid/Empty response
    monkeypatch.setattr(
        aws_service.dev_client,
        "list_resource_record_sets",
        aws_list_resource_record_sets_mock,
    )
    assert not (
        aws_service.check_record_exist(
            hosted_zone_id="empty",
            record_name="example.cba.com.au",
            record_type="TXT",
            env="dev",
        )
    )


def test_process_txt_record(monkeypatch) -> None:
    # Success case
    monkeypatch.setattr(
        aws_service, "update_txt_record_by_env", updated_txt_record_by_env_mock
    )
    try:
        aws_service.process_txt_record(
            domain_name="valid",
            record_name="record_name",
            record_value="record_value",
        )
    except Exception as e:
        pytest.fail(f"test_process_txt_record failed: {e}")

    # Invalid domain name - hosted zone id not found
    with pytest.raises(exceptions.AWSServiceRoute53RecordNotFoundException):
        aws_service.process_txt_record(
            domain_name="invalid", record_name="record_name", record_value="record_value"
        )
    # Invalid domain name - raises exception
    with pytest.raises(exceptions.AWSServiceRoute53InvalidInputException):
        aws_service.process_txt_record(
            domain_name="", record_name="record_name", record_value="record_value"
        )


def test_update_txt_record_by_env(monkeypatch) -> None:
    monkeypatch.setattr(
        aws_service,
        "get_hosted_zone_id_by_domain",
        get_hosted_zone_id_by_domain_mock,
    )
    monkeypatch.setattr(
        aws_service,
        "check_record_exist",
        check_record_exist_mock,
    )
    monkeypatch.setattr(
        aws_service,
        "change_resource_record_sets",
        change_resource_record_sets_mock,
    )
    # Success case
    assert aws_service.update_txt_record_by_env(
        domain_name="example.cba.com.au",
        record_name="valid",
        record_value="test",
        env="dev",
    )
    # Invalid domain name - hosted zone id not found
    assert not aws_service.update_txt_record_by_env(
        domain_name="invalid",
        record_name="cloudflare-verify.example.cba.com.au",
        record_value="test",
        env="dev",
    )

    called_count = {"count": 0}

    def change_resource_record_sets_mock_with_count(
        env=None,
        hosted_zone_id=None,
        record_name=None,
        record_value=None,
        record_type=None,
        ttl=None,
    ):
        called_count["count"] += 1
        return None

    monkeypatch.setattr(
        aws_service,
        "change_resource_record_sets",
        change_resource_record_sets_mock_with_count,
    )
    # TXT record already exists
    aws_service.update_txt_record_by_env(
        domain_name="example.cba.com.au",
        record_name="txt_already_exists",
        record_value="test",
        env="dev",
    )
    assert called_count["count"] == 0


# Mock responses
def aws_list_hosted_zones_by_name_mock(DNSName, MaxItems="1"):
    if not DNSName:
        return {}
    if DNSName == "example.cba.com.aa":
        DNSName = "invalid.cba.com.au"
    return {
        "HostedZones": [
            {
                "Id": "/hostedzone/123456789",
                "Name": f"{DNSName}.",
                "CallerReference": "test20150527-1",
            }
        ],
        "IsTruncated": False,
        "MaxItems": "100",
    }


def aws_change_resource_record_sets_mock(HostedZoneId=None, ChangeBatch=None):
    if HostedZoneId == "empty":
        return {}
    if HostedZoneId == "status_code_not_200":
        return {"ResponseMetadata": {"HTTPStatusCode": 404}}
    if HostedZoneId == "exception":
        raise Exception()
    return {
        "ResponseMetadata": {
            "RequestId": "443956dc-5e9a-42b2-af51-deac4199c5ab",
            "HTTPStatusCode": 200,
            "HTTPHeaders": {},
            "RetryAttempts": 0,
        },
        "ChangeInfo": {
            "Id": "/change/C069442720W0JDWWGSCKA",
            "Status": "PENDING",
            "SubmittedAt": "",
            "Comment": "Test",
        },
    }


def aws_list_resource_record_sets_mock(
    HostedZoneId=None, StartRecordName=None, StartRecordType=None, MaxItems="1"
):
    if HostedZoneId == "empty":
        return {}
    Name = "example.cba.com.au."
    if HostedZoneId == "not_found":
        Name = "not_found.cba.com.au."
    response = {
        "ResourceRecordSets": [
            {
                "Name": Name,
                "Type": "TXT",
                "TTL": 300,
                "ResourceRecords": [{"Value": "test"}],
            }
        ]
    }
    return response


def updated_txt_record_by_env_mock(
    domain_name, record_name, record_value, env
):
    if domain_name == "valid":
        return True
    return False


def get_hosted_zone_id_by_domain_mock(domain_name=None, env=None):
    if domain_name == "invalid":
        return None
    return "/hostedzone/123456789"


def check_record_exist_mock(
    hosted_zone_id=None, record_name=None, record_type=None, env=None
):
    if record_type == "NS" or record_name == "txt_already_exists":
        return True
    return False


def change_resource_record_sets_mock(
    env=None,
    hosted_zone_id=None,
    record_name=None,
    record_value=None,
    record_type=None,
    ttl=None,
):
    if record_name == "valid":
        return True
    return False
