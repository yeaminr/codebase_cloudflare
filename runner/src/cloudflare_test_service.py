import logging
import os
import sys
import zipfile
from io import StringIO

from fastapi import HTTPException
import pytest

from runner.src import helpers
from runner.src import api_constant, exceptions, github_service
from runner.src import working_dir as wd
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src.model import InputModel, TestInputModel
import base64

logger = logging.getLogger(__name__)

    
def create_test_session(
    test_inputs: TestInputModel, 
    jwt_token_info: JWTTokenInfo, 
    input_model: InputModel
):
    """
    Create a test session
    """
    
    logging.info("Creating test session")
    
    cwd = wd.create_dir()
    if cwd is None:
        raise HTTPException(
            status_code=500, 
            detail="Error running test service: Failed to create working directory"
        )
    
    _get_tenant_config_files(jwt_token_info, input_model, cwd)
    
    os.environ["ES_ENV"] = input_model.environment
    os.environ["CF_TENANT_DOMAIN"] = test_inputs.fqdn
    os.environ["TENANT_REPO"] = test_inputs.report_inputs.tenant_repo
    os.environ["GITHUB_RUN_ID"] = test_inputs.report_inputs.github_run_id
    
    test_report_dir = f"{cwd}/{api_constant.TEST_REPORT_DIRECTORY}"
    
    # Capture stdout
    old_stdout = sys.stdout
    sys.stdout = StringIO()

    try:
        logger.info("Starting PyTest Execution")
        exit_code = pytest.main([
            "testing/pytest_framework",
            "-vv",
            "-c",  "testing/pytest_framework/pytest.ini",
            f"--log-cli-level={test_inputs.log_level}",
            f"--junitxml={test_report_dir}/TEST_result.xml",
            f"--html={test_report_dir}/TEST_result.html",
            "-m", f"{test_inputs.test_tags} and not runnertests"
            ])
        logger.info(f"PyTest execution completed with exit code: {exit_code}")
        stdout_output = sys.stdout.getvalue()  # Save stdout to variable
        test_artefacts = _get_test_artefacts(cwd)
    except Exception as e:
        logger.error(f"Unexpected exception from test service: {e}")
        raise HTTPException(status_code=500, detail=f"Error running test service: {e}")
    finally:
        # Restore stdout
        sys.stdout.close()
        sys.stdout = old_stdout
        
        # Clear environment variables
        os.environ.pop("ES_ENV", None)
        os.environ.pop("CF_TENANT_DOMAIN", None)
        os.environ.pop("TENANT_REPO", None)
        os.environ.pop("GITHUB_RUN_ID", None)
        os.environ.pop("CLOUDFLARE_TOKEN_ID", None)
        os.environ.pop("CLOUDFLARE_TOKEN", None)
        os.environ.pop("CLOUDFLARE_ACCOUNT_TOKEN_ID", None)
        os.environ.pop("CLOUDFLARE_ACCOUNT_TOKEN", None)
        
        wd.delete_dir(cwd)
    
    response = {
        "exit_code": exit_code,
        "stdout": stdout_output,
        "test_artefacts": test_artefacts
    }

    return response


def _get_tenant_config_files(
    jwt_token_info: JWTTokenInfo, 
    input_model: InputModel, 
    cwd: str,
):
    """
    Get all tenant input YAML files. Save the file names in environment variables
    """
    logger.info("Retrieving Tenant Config Files for Testing")    
    config_list = api_constant.TENANT_ALLOWED_CONFIGS
    
    for config in config_list:
        try:            
            input_vars_path = helpers.get_input_vars_path(
                input_model.environment, 
                input_model.fqdn,
                config
            )
            
            input_url = github_service.get_download_url(
                jwt_token_info.repo_name,
                input_vars_path,
                jwt_token_info.branch_name
            )
            
            github_service.get_file_content(input_url, cwd)
        except (exceptions.GithubServiceException, Exception) as e:
            logger.warning("Error running Github service: %s", e)
        
    os.environ["CF_TLS_CONFIG_FILE"]            = f"{cwd}/tls_parameters.yml"
    os.environ["CF_CDN_CONFIG_FILE"]            = f"{cwd}/cdn_parameters.yml"
    os.environ["CF_SECURITY_CONFIG_FILE"]       = f"{cwd}/security_parameters.yml"
    os.environ["CF_CERTIFICATE_CONFIG_FILE"]    = f"{cwd}/cert_parameters.yml"
    os.environ["CF_MTLS_CONFIG_FILE"]           = f"{cwd}/mtls_parameters.yml"
    os.environ["CF_MTLS_BUNDLE_DIRECTORY"]      = f"{cwd}/bundles"
    os.environ["CF_WORKERS_CONFIG_FILE"]        = f"{cwd}/workers_parameters.yml"
    os.environ["CF_APP_LIST_CONFIG_FILE"]       = f"{cwd}/app_list_parameters.yml"


def _zip_test_reports(folder_path, output_zip_path):
    """
    Compress all files within a folder into a zip archive.

    Paremeters:
    folder_path: Path to the folder to be zipped.
    output_zip_path: Path where the zip file will be created.
    
    Returns:
    str: Path to the created zip file.
    """
    logger.info("Zipping Test Reports")
    if not os.path.isdir(folder_path):
        raise NotADirectoryError(f"The folder {folder_path} does not exist or is not a directory.")
    
    with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, start=folder_path)
                zipf.write(file_path, arcname)
    
    return output_zip_path


def _get_test_artefacts(cwd):
    """
    Get the test artefacts for a test session
    """
    logger.info("Retrieving test execution artefacts")
    test_report_dir = f"{cwd}/{api_constant.TEST_REPORT_DIRECTORY}"
    test_results_dir = f"{test_report_dir}/"
    zip_file = f"{test_report_dir}.zip"
    
    try:
        output_zip_path = _zip_test_reports(test_results_dir, zip_file)
    except Exception as e:
        logger.error(f"Error zipping test reports: {e}")
        return ""
    
    # Convert the zip file to a base64 encoded string
    try:
        base64_encoded_zip = _convert_file_to_base64(output_zip_path)
    except Exception as e:
        logger.error(f"Error converting zip file to base64: {e}")
        return ""

    return base64_encoded_zip


def _convert_file_to_base64(file_path):
    """
    Convert a file to a base64 encoded string.

    Parameters:
    file_path: Path to the file to be encoded.

    Returns:
    str: Base64 encoded string of the file content.
    """
    logger.info("Converting test artefacts to Base64 string")
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file {file_path} does not exist.")
    
    try:
        with open(file_path, "rb") as file:
            encoded_string = base64.b64encode(file.read()).decode("utf-8")
        logger.info(f"Successfully converted file to base64: {file_path}")
        return encoded_string
    except Exception as e:
        logger.error(f"Error converting file {file_path} to base64: {e}")
        raise