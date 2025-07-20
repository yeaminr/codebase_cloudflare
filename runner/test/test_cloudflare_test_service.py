import pytest
from runner.src.cloudflare_test_service import (
        create_test_session,
        _get_tenant_config_files,
        _zip_test_reports,
        _get_test_artefacts,
        _convert_file_to_base64,
    )
from runner.src.model import TestInputModel, InputModel
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src.model import InputModel
import os


@pytest.fixture
def mock_test_inputs():
    return TestInputModel(
        fqdn="www.example.com",
        report_inputs=TestInputModel.ReportInputs(tenant_repo="test_repo", github_run_id="12345"),
        log_level="warning",
        test_tags="test_tag"
    )


@pytest.fixture
def mock_jwt_token_info():
    return JWTTokenInfo(repo_name="test_repo", branch_name="main", org_name="test_org", authorized=True)


@pytest.fixture
def mock_input_model():
    return InputModel(environment="dev", action="plan", config_type="zone", fqdn="www.example.com")


def test_create_test_session(monkeypatch, mock_test_inputs, mock_jwt_token_info, mock_input_model):
    # Mock dependencies
    mock_cwd = "/mock_cwd"
    def mock_create_dir(*args, **kwargs):
        return mock_cwd

    def mock_pytest_main(*args, **kwargs):
        return 0

    def mock_delete_dir(path):
        assert path == mock_cwd

    def mock_get_test_artefacts(*args, **kwargs):
        return "mock_artefacts"

    monkeypatch.setattr("runner.src.working_dir.create_dir", mock_create_dir)
    monkeypatch.setattr("runner.src.working_dir.delete_dir", mock_delete_dir)
    monkeypatch.setattr("runner.src.cloudflare_test_service._get_test_artefacts", mock_get_test_artefacts)
    monkeypatch.setattr("pytest.main", mock_pytest_main)

    # Run the function
    response = create_test_session(mock_test_inputs, mock_jwt_token_info, mock_input_model)

    # Assertions
    assert response["exit_code"] == 0
    assert response["stdout"] is not None
    assert response["test_artefacts"] == "mock_artefacts"
    

def test_get_tenant_config_files(monkeypatch, mock_jwt_token_info, mock_input_model):
    mock_cwd = "/mock_cwd"
    mock_config_list = ["cdn_parameters.yml", "security_parameters.yml"]

    def mock_get_input_vars_path(environment, fqdn, config):
        return f"{environment}/{fqdn}/{config}"

    def mock_get_download_url(repo_name, input_vars_path, branch_name):
        return f"https://mock_url/{input_vars_path}"

    def mock_get_file_content(input_url, cwd):
        assert input_url.startswith("https://mock_url/")
        assert cwd == mock_cwd

    monkeypatch.setattr("runner.src.api_constant.TENANT_ALLOWED_CONFIGS", mock_config_list)
    monkeypatch.setattr("runner.src.helpers.get_input_vars_path", mock_get_input_vars_path)
    monkeypatch.setattr("runner.src.github_service.get_download_url", mock_get_download_url)
    monkeypatch.setattr("runner.src.github_service.get_file_content", mock_get_file_content)

    _get_tenant_config_files(mock_jwt_token_info, mock_input_model, mock_cwd)

    assert os.environ["CF_CDN_CONFIG_FILE"] == f"{mock_cwd}/cdn_parameters.yml"
    assert os.environ["CF_SECURITY_CONFIG_FILE"] == f"{mock_cwd}/security_parameters.yml"


def test_zip_test_reports(tmp_path):
    folder_path = tmp_path / "test_folder"
    folder_path.mkdir()
    (folder_path / "file1.txt").write_text("content1")
    (folder_path / "file2.txt").write_text("content2")
    output_zip_path = tmp_path / "output.zip"

    result = _zip_test_reports(str(folder_path), str(output_zip_path))

    assert os.path.exists(result)
    assert result == str(output_zip_path)


def test_get_test_artefacts(monkeypatch, tmp_path):
    mock_cwd = str(tmp_path)
    test_results_dir = f"{mock_cwd}/test_reports"
    os.makedirs(test_results_dir)
    (tmp_path / "test_reports" / "file.txt").write_text("test content")
    zip_file = f"{mock_cwd}/test_reports.zip"

    def mock_zip_test_reports(folder_path, output_zip_path):
        return output_zip_path

    def mock_convert_file_to_base64(file_path):
        return "mock_base64"

    monkeypatch.setattr("runner.src.cloudflare_test_service._zip_test_reports", mock_zip_test_reports)
    monkeypatch.setattr("runner.src.cloudflare_test_service._convert_file_to_base64", mock_convert_file_to_base64)

    result = _get_test_artefacts(mock_cwd)

    assert result == "mock_base64"


def test_convert_file_to_base64(tmp_path):
    file_path = tmp_path / "test_file.txt"
    file_path.write_text("test content")

    result = _convert_file_to_base64(str(file_path))

    assert result is not None
    assert isinstance(result, str)
