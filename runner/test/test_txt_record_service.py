import pytest
import yaml
from runner.src import (
    github_service,
    txt_record_service,
    aws_service,
)
from runner.src import exceptions
from runner.src.model import InputModel


# Test
def test_process_txt_record(monkeypatch):
    called_count = {"bw": 0, "cba": 0}
    # Process Bankwest TXT record
    model = InputModel(
        environment="dev",
        action="apply",
        config_type="zone",
        fqdn="stkn-stg.bankwest.com.au",
        change_number="CHG123456",
    )

    def process_bankwest_txt_record_with_count(
        model=None,
        txt_record_value=None,
    ):
        called_count["bw"] += 1
        return None

    monkeypatch.setattr(
        txt_record_service,
        "process_bankwest_txt_record",
        process_bankwest_txt_record_with_count,
    )
    txt_record_service.process_txt_record(model, "txt_record_name", "txt_record_value")
    assert called_count["bw"] == 1
    # Process CBA TXT record
    model.fqdn = "stkn-stg.cba.com.au"

    def process_cba_txt_record_with_count(
        model=None,
        txt_record_name=None,
        txt_record_value=None,
        cwd=None,
    ):
        called_count["cba"] += 1
        return None

    monkeypatch.setattr(
        aws_service, "process_txt_record", process_cba_txt_record_with_count
    )
    txt_record_service.process_txt_record(model, "txt_record_name", "txt_record_value")
    assert called_count["cba"] == 1


def test_process_bankwest_txt_record(monkeypatch):
    # Success case - no updated yaml content
    called_count = {"create_pr": 0, "update_file": 0, "create_branch": 0}

    def create_github_branch_with_count(
        repo=None,
        branch=None,
        sha=None,
    ):
        called_count["create_branch"] += 1
        return None

    def update_github_file_with_count(
        repo=None,
        feature=None,
        file_path=None,
        updated_yaml_content=None,
        commit_message=None,
    ):
        called_count["update_file"] += 1
        return None

    def create_github_pr_with_count(
        repo=None,
        branch=None,
        title=None,
        body=None,
        base=None,
    ):
        called_count["create_pr"] += 1
        return None

    model = InputModel(
        environment="dev",
        action="apply",
        config_type="zone",
        fqdn="stkn-stg.bankwest.com.au",
        change_number="CHG123456",
    )
    monkeypatch.setattr(
        txt_record_service,
        "updated_fqdn_yaml_content",
        lambda fqdn, txt_record_value: (None, None),
    )
    txt_record_service.process_bankwest_txt_record(model, "txt_record_value")
    assert called_count["create_pr"] == 0
    assert called_count["update_file"] == 0
    assert called_count["create_branch"] == 0
    # Success case - create branch, update file, create PR
    called_count = {"create_pr": 0, "update_file": 0, "create_branch": 0}  # Reset
    monkeypatch.setattr(
        txt_record_service,
        "updated_fqdn_yaml_content",
        lambda fqdn, txt_record_value: ("updated_yaml_content", "file_path"),
    )
    monkeypatch.setattr(
        github_service,
        "get_github_sha",
        lambda repo, branch: "main_branch_sha",
    )
    monkeypatch.setattr(
        github_service,
        "get_repo_branch",
        mock_branch_not_found_exception,
    )
    monkeypatch.setattr(
        github_service,
        "get_file_content",
        lambda url: "fqdn_yaml_content",
    )
    monkeypatch.setattr(
        github_service,
        "update_github_file",
        update_github_file_with_count,
    )
    monkeypatch.setattr(
        github_service,
        "create_github_pr",
        create_github_pr_with_count,
    )
    monkeypatch.setattr(
        github_service,
        "create_github_branch",
        create_github_branch_with_count,
    )
    txt_record_service.process_bankwest_txt_record(model, "txt_record_value")
    assert called_count["create_pr"] == 1
    assert called_count["update_file"] == 1
    assert called_count["create_branch"] == 1
    # Success case - create branch, no update file, create PR
    called_count = {"create_pr": 0, "update_file": 0, "create_branch": 0}  # Reset
    monkeypatch.setattr(
        github_service,
        "get_file_content",
        lambda url: "updated_yaml_content",
    )
    txt_record_service.process_bankwest_txt_record(model, "txt_record_value")
    assert called_count["create_pr"] == 1
    assert called_count["update_file"] == 0
    assert called_count["create_branch"] == 1
    # Success case - no create branch, no update file, create PR
    called_count = {"create_pr": 0, "update_file": 0, "create_branch": 0}  # Reset
    monkeypatch.setattr(
        github_service,
        "get_repo_branch",
        lambda repo, branch: {"name": "feature_branch_exists"},
    )
    txt_record_service.process_bankwest_txt_record(model, "txt_record_value")
    assert called_count["create_pr"] == 1
    assert called_count["update_file"] == 0
    assert called_count["create_branch"] == 0


def test_updated_fqdn_yaml_content(monkeypatch):
    def get_file_content_mock(file_url):
        if "stkn-stg.bankwest.com.au" in file_url:
            raise exceptions.GithubServiceFileFetchException("File not found")
        if "only_ns_record" in file_url:
            return yaml.dump(
                {
                    "": [
                        {
                            "type": "NS",
                            "ttl": "172800",
                            "value": ["ns-360.awsdns-45.com"],
                        }
                    ]
                }
            )
        if "no_ns_record" in file_url:
            return yaml.dump({})
        return file_content_with_ns_txt_record

    # NS and TXT record already exists - Do nothing
    file_content_with_ns_txt_record = yaml.dump(
        {
            "": [{"type": "NS", "ttl": "172800", "value": ["ns-360.awsdns-45.com"]}],
            "cloudflare-verify.stkn-stg": {
                "type": "TXT",
                "ttl": "300",
                "value": ["txt_record_value"],
            },
        }
    )
    monkeypatch.setattr(
        github_service,
        "get_file_content",
        get_file_content_mock,
    )
    updated_yaml_content, file_path = txt_record_service.updated_fqdn_yaml_content(
        "stkn-stg.bankwest.com.au", "txt_record_value"
    )
    assert not updated_yaml_content
    assert not file_path
    # NS record exists, TXT record does not exist - Add TXT record
    file_content_with_ns_record = yaml.dump(
        {
            "": [{"type": "NS", "ttl": "172800", "value": ["ns-360.awsdns-45.com"]}],
            "cloudflare-verify": {
                "type": "TXT",
                "ttl": 300,
                "value": "txt_record_value",
            },
        }
    )
    monkeypatch.setattr(
        github_service,
        "get_file_content",
        get_file_content_mock,
    )
    updated_yaml_content, file_path = txt_record_service.updated_fqdn_yaml_content(
        "only_ns_record.bankwest.com.au", "txt_record_value"
    )
    assert file_path == "octodns/zones/only_ns_record.bankwest.com.au.yaml"
    assert yaml.safe_load(updated_yaml_content) == yaml.safe_load(
        file_content_with_ns_record
    )
    # NS record does not exist - Raise exception
    with pytest.raises(exceptions.TextRecordServiceException):
        txt_record_service.updated_fqdn_yaml_content(
            "no_ns_record.com.au", "txt_record_value"
        )


def mock_branch_not_found_exception(*args, **kwargs):
    raise exceptions.GithubServiceBranchNotFoundException()