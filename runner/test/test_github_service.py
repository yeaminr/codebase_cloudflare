import pytest
import jwt
import yaml
from runner.src import github_service
from runner.src import api_constant
from runner.src import exceptions
from runner.src import working_dir as wd
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src.model import InputModel


# Tests
def test_get_file_content(monkeypatch, requests_mock) -> None:
    # Restricted org - Success scenario
    monkeypatch.setattr(api_constant, "gh_rstd_org_installation_id", "installation_id")
    monkeypatch.setattr(
        github_service, "generate_installation_jwt", generate_installation_jwt_mock
    )
    monkeypatch.setattr(
        github_service, "download_file_content", download_file_content_mock
    )
    requests_mock.get(
        "https://api.github.com/repos/CBA-Edge-Security-Platform-RSTD/test",
        json={"content": "dGVzdA=="},
    )
    github_service.get_file_content(
        "https://api.github.com/repos/CBA-Edge-Security-Platform-RSTD/test", "wd"
    )


def test_main(monkeypatch, requests_mock) -> None:
    monkeypatch.setattr(
        github_service, "generate_installation_jwt", generate_installation_jwt_mock
    )
    monkeypatch.setattr(
        github_service, "download_file_content", download_file_content_mock
    )
    requests_mock.get(
        "https://api.github.com/repos/esm-repo/contents/dev/example.com.au/zone_parameters.yml?ref=feature/pytest",
        json={"content": "dGVzdA=="},
    )
    jwt_token_info = JWTTokenInfo(
        authorized=True,
        repo_name="esm-repo",
        org_name="esm-org",
        branch_name="feature/pytest",
    )
    input_model = InputModel(
        environment="dev", fqdn="example.com.au", config_type="zone"
    )
    github_service.main(
        jwt_token_info=jwt_token_info,
        input_model=input_model,
        working_dir="working_dir",
    )
    requests_mock.get(
        "https://api.github.com/repos/esm-repo/contents/dev/example.com.au/zone_parameters.yml?ref=feature/pytest",
        text="test",
    )
    with pytest.raises(ValueError):
        github_service.main(
            jwt_token_info=jwt_token_info,
            input_model=input_model,
            working_dir="working_dir",
        )
    requests_mock.get(
        "https://api.github.com/repos/esm-repo/contents/dev/example.com.au/zone_parameters.yml?ref=feature/pytest",
        text="Not Found",
        status_code=404,
    )
    with pytest.raises(exceptions.GithubServiceFileFetchException):
        github_service.main(
            jwt_token_info=jwt_token_info,
            input_model=input_model,
            working_dir="working_dir",
        )
    # Testing worker config type
    requests_mock.get(
        "https://api.github.com/repos/esm-repo/contents/dev/example.com.au/workers/workers_parameters.yml?ref=feature/pytest",
        json={"content": "dGVzdA=="},
    )
    requests_mock.get(
        "https://api.github.com/repos/esm-repo/contents/dev/example.com.au/zone_parameters.yml?ref=feature/pytest",
        json={"content": "dGVzdA=="},
    )
    input_model = InputModel(
        environment="dev", fqdn="example.com.au", config_type="workers"
    )
    monkeypatch.setattr(github_service, "load_parameters_yaml", lambda x, y: None)
    monkeypatch.setattr(
        github_service, "get_workers_js_list", lambda x, y: ["file1", "file2"]
    )
    monkeypatch.setattr(
        github_service, "get_multiple_file_content", lambda x, y, z, a: None
    )
    github_service.main(
        jwt_token_info=jwt_token_info,
        input_model=input_model,
        working_dir="working_dir",
    )


def test_generate_installation_jwt(monkeypatch, requests_mock) -> None:
    # Installation id empty - Error scenario
    with pytest.raises(exceptions.GithubServiceException):
        github_service.generate_installation_jwt(None)
    # Github api error - Error scenario
    monkeypatch.setattr(api_constant, "gh_signing_key", "gh_signing_key")
    monkeypatch.setattr(api_constant, "gh_app_id", "1")
    monkeypatch.setattr(jwt, "encode", jwt_encode_mock)
    requests_mock.post(
        "https://api.github.com/app/installations/1/access_tokens",
        json={"token": "error"},
        status_code=500,
    )
    with pytest.raises(ValueError):
        github_service.generate_installation_jwt(1)
    # Success scenario
    requests_mock.post(
        "https://api.github.com/app/installations/1/access_tokens",
        json={"token": "secret"},
        status_code=201,
    )
    token = github_service.generate_installation_jwt(1)
    assert token == "secret"


def test_get_multiple_file_content(monkeypatch):
    monkeypatch.setattr(github_service, "get_file_content", lambda x, y: None)
    assert (
        github_service.get_multiple_file_content(
            "repo", "ref", ["file1", "file2"], "working_dir"
        )
        is None
    )


def test_load_parameters_yaml(monkeypatch) -> None:
    # Success
    cwd = wd.create_dir()
    data = {"worker_configs": [{"script_name": "noname", "script_file": "noname.js"}]}
    with open(f"{cwd}/workers_parameters.yml", "w", encoding="utf-8") as file:
        yaml.dump(data, file)
    assert github_service.load_parameters_yaml(cwd, "workers") == data
    wd.delete_dir(cwd)
    # Error
    cwd = wd.create_dir()
    data = None
    with open(f"{cwd}/workers_parameters.yml", "w", encoding="utf-8") as file:
        yaml.dump(data, file)
    with pytest.raises(exceptions.GithubServiceException):
        github_service.load_parameters_yaml(cwd, "workers")
    wd.delete_dir(cwd)


def test_get_workers_js_list(monkeypatch) -> None:
    # Success scenario - Zone worker config
    input_model = InputModel(
        environment="dev", fqdn="example.com.au", config_type="workers"
    )
    workers_config = {"worker_configs": []}
    assert github_service.get_workers_js_list(input_model, workers_config) == []

    workers_config = {"worker_configs": [{"script_file": "zone_worker.js"}]}
    assert github_service.get_workers_js_list(input_model, workers_config) == [
        "dev/example.com.au/workers/zone_worker.js"
    ]
    # Success scenario - Account worker config
    input_model = InputModel(environment="dev", fqdn=None, config_type="account")
    workers_config = {"noname_configs": {"script_file": "noname.js"}}
    assert github_service.get_workers_js_list(input_model, workers_config) == [
        "dev/noname.js"
    ]
    input_model = InputModel(environment="dev", fqdn=None, config_type="account")
    workers_config = {
        "noname_configs": {"script_file": "noname.js"},
        "worker_configs": [{"script_file": "account_worker.js"}],
    }
    assert github_service.get_workers_js_list(input_model, workers_config) == [
        "dev/noname.js",
        "dev/account_worker.js",
    ]


def test_get_github_sha(monkeypatch, requests_mock) -> None:
    monkeypatch.setattr(github_service, "generate_installation_jwt", lambda x: "token")
    # Success
    requests_mock.get(
        "https://api.github.com/repos/test-org/test-repo/commits/main",
        json={"sha": "sha"},
        status_code=200,
    )
    assert github_service.get_github_sha("test-org/test-repo", "main") == "sha"
    # Error
    requests_mock.get(
        "https://api.github.com/repos/CBA-Edge-Security-Platform-RSTD/test-repo/commits/main",
        text="Not Found",
        status_code=404,
    )
    with pytest.raises(exceptions.GithubServiceException):
        github_service.get_github_sha(
            "CBA-Edge-Security-Platform-RSTD/test-repo", "main"
        )


def test_create_github_branch(monkeypatch, requests_mock) -> None:
    monkeypatch.setattr(github_service, "generate_installation_jwt", lambda x: "token")
    # Success
    requests_mock.post(
        "https://api.github.com/repos/test-org/test-repo/git/refs",
        json={"ref": "refs/heads/featureA"},
        status_code=201,
    )
    assert (
        github_service.create_github_branch("test-org/test-repo", "featureA", "sha")
        == {"ref": "refs/heads/featureA"}
    )
    # Error
    requests_mock.post(
        "https://api.github.com/repos/test-org/test-repo/git/refs",
        text="Not Found",
        status_code=404,
    )
    with pytest.raises(exceptions.GithubServiceException):
        github_service.create_github_branch("test-org/test-repo", "featureA", "sha")


def test_create_github_pr(monkeypatch, requests_mock) -> None:
    monkeypatch.setattr(github_service, "generate_installation_jwt", lambda x: "token")
    # Success
    requests_mock.post(
        "https://api.github.com/repos/test-org/test-repo/pulls",
        json={"number": 1},
        status_code=201,
    )
    try:
        github_service.create_github_pr(
            "test-org/test-repo", "featureA", "title", "body"
        )
    except exceptions.GithubServiceException:
        pytest.fail("create_github_pr() raised GithubServiceException unexpectedly!")
    # Pull request already exists
    requests_mock.post(
        "https://api.github.com/repos/test-org/test-repo/pulls",
        json={"errors": [{"message": "A pull request already exists for featureA"}]},
        status_code=422,
    )
    try:
        github_service.create_github_pr(
            "test-org/test-repo", "featureA", "title", "body"
        )
    except exceptions.GithubServiceException:
        pytest.fail("create_github_pr() raised GithubServiceException unexpectedly!")
    # Error
    requests_mock.post(
        "https://api.github.com/repos/test-org/test-repo/pulls",
        json={"errors": [{"message": "Something went wrong"}]},
        status_code=500,
    )
    with pytest.raises(exceptions.GithubServiceException):
        github_service.create_github_pr("test-org/test-repo", "featureA", "title", "body")


def test_update_github_file(monkeypatch, requests_mock) -> None:
    monkeypatch.setattr(github_service, "generate_installation_jwt", lambda x: "token")
    # Success
    requests_mock.get(
        "https://api.github.com/repos/test-org/test-repo/contents/test-file?ref=featureA",
        json={"sha": "sha"},
        status_code=200,
    )
    requests_mock.put(
        "https://api.github.com/repos/test-org/test-repo/contents/test-file",
        json={"content": "dGVzdA=="},
        status_code=200,
    )
    assert (
        github_service.update_github_file(
            "test-org/test-repo", "featureA", "test-file", "test", "commit-message"
        )
        == {"content": "dGVzdA=="}
    )
    # Error - Unable to get file - SHA not found
    requests_mock.get(
        "https://api.github.com/repos/test-org/test-repo/contents/test-file?ref=featureA",
        text="Not Found",
        status_code=404,
    )
    with pytest.raises(exceptions.GithubServiceException):
        github_service.update_github_file(
            "test-org/test-repo", "featureA", "test-file", "test", "commit"
        )
    # Error - Unable to update file
    requests_mock.get(
        "https://api.github.com/repos/test-org/test-repo/contents/test-file?ref=featureA",
        json={"sha": "sha"},
        status_code=200,
    )
    requests_mock.put(
        "https://api.github.com/repos/test-org/test-repo/contents/test-file",
        json={"content": "dGVzdA=="},
        status_code=500,
    )
    with pytest.raises(exceptions.GithubServiceException):
        github_service.update_github_file(
            "test-org/test-repo", "featureA", "test-file", "test", "commit"
        )


def test_get_repo_branch(monkeypatch, requests_mock) -> None:
    monkeypatch.setattr(github_service, "generate_installation_jwt", lambda x: "token")
    # Success
    requests_mock.get(
        "https://api.github.com/repos/test-org/test-repo/branches/featureA",
        json={"commit": {"sha": "sha"}},
        status_code=200,
    )
    assert github_service.get_repo_branch("test-org/test-repo", "featureA") == {"commit": {"sha": "sha"}}
    # Error
    requests_mock.get(
        "https://api.github.com/repos/test-org/test-repo/branches/featureA",
        text="Not Found",
        status_code=404,
    )
    with pytest.raises(exceptions.GithubServiceBranchNotFoundException):
        github_service.get_repo_branch("test-org/test-repo", "featureA")


def test_download_file_content(monkeypatch) -> None:
    # Success
    cwd = wd.create_dir()
    github_service.download_file_content("Test", "test.tf", cwd)
    wd.delete_dir(cwd)

    # Error
    with pytest.raises(FileNotFoundError):
        github_service.download_file_content("Test", "test.tf", "dir_not_exist")


# # Mocks
def jwt_encode_mock(payload, signing_key, algorithm) -> str:
    return "encoded_jwt"


def generate_installation_jwt_mock(installation_id) -> str:
    return "test-token"


def download_file_content_mock(response_json, file_name, working_dir) -> str:
    return
