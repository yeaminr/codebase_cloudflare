import time
import os
import logging
import base64
import requests
import jwt
from runner.src import api_constant
from runner.src import exceptions
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src.model import InputModel
from cf.python.src import helpers

logger = logging.getLogger(__name__)

def get_headers():
    """
    Get the headers for the Github API
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    return headers


def main(
    jwt_token_info: JWTTokenInfo,
    input_model: InputModel,
    working_dir: str,
):
    """
    Main function to run the Github service to download the config yaml from Github using Github app creds
    """
    logger.info(
        "Running the Github Service for zone %s & environment %s for the config type %s in working dir %s",
        input_model.fqdn,
        input_model.environment.value,
        input_model.config_type,
        working_dir,
    )
    repo_name = jwt_token_info.repo_name
    repo_ref = jwt_token_info.branch_name
    try:
        input_vars_path = helpers.get_input_vars_path(
            input_model.environment, input_model.fqdn, input_model.config_type
        )
    except ValueError as e:
        logger.error(e)
        raise exceptions.GithubServiceInvalidInputPathException(
            "Invalid input vars path"
        )

    input_url = get_download_url(repo_name, input_vars_path, repo_ref)
    if input_url:
        # get input yaml file
        get_file_content(input_url, working_dir)
    else:
        raise ValueError("Invalid input url")

    if input_model.config_type in ["cdn", "security", "tls"]:
        # get zone_parameters.yml file
        zone_parameters_url = (
            f"https://api.github.com/repos/{repo_name}/contents/"
            f"{input_model.environment.value}/{input_model.fqdn}/zone_parameters.yml?ref={repo_ref}"
        )
        get_file_content(zone_parameters_url, working_dir)


def get_download_url(repo, path, ref):
    """
    Get the download URL for the file from Github
    """
    if repo and path and ref:
        return f"https://api.github.com/repos/{repo}/contents/{path}?ref={ref}"
    else:
        return None


def get_verify_ssl():
    """
    Get the verify_ssl flag based on the environment - ONLY FOR LOCAL TESTING
    """
    verify_ssl = True
    if api_constant.local:
        verify_ssl = False
    return verify_ssl


def get_file_content(url: str, working_dir: str | None) -> dict:
    """
    Get the file content from the Github API

    Args
    ----
    url (str): The URL to fetch the file content from
    working_dir (str): The working directory to save the file content
    """
    auth_headers = get_headers()
    auth_headers["Authorization"] = f"Bearer {generate_installation_jwt()}"
    logger.info("Getting input yaml content %s", url)
    response = requests.get(url, headers=auth_headers, verify=get_verify_ssl())
    if response.status_code == 200:
        if isinstance(response.json(), dict):
            file_content_decoded = base64.b64decode(response.json().get("content"))
            file_content = file_content_decoded.decode("utf-8")
            file_name = response.json().get("name")
            if working_dir:
                download_file_content(file_content, file_name, working_dir)
            return file_content
    logger.error("Unable to fetch the content from Github: %s", response.status_code)
    logger.error(response.text)
    raise exceptions.GithubServiceFileFetchException(
        f"Unable to fetch the content from Github for the URL: {url}"
    )


def download_file_content(file_content, file_name, working_dir):
    """
    Download the file content to the working directory

    Args
    ----
    response_json (dict): The response JSON from the Github API
    working_dir (str): The working directory to save the file content
    """
    if os.path.exists(working_dir):
        with open(
            working_dir + "/" + file_name, "w", encoding="UTF-8"
        ) as file:
            file.write(file_content)
    else:
        logger.error("Directory %s does not exist", working_dir)
        raise FileNotFoundError(f"Directory {working_dir} does not exist")


def generate_jwt():
    """
    Generate the JWT token for the Github API using the app credentials
    """
    signing_key = api_constant.gh_signing_key.replace("\\n", "\n")
    client_id = api_constant.gh_app_id
    payload = {"iat": int(time.time()), "exp": int(time.time()) + 600, "iss": client_id}
    logger.info("Generating JWT token")
    encoded_jwt = jwt.encode(payload, signing_key, algorithm="RS256")
    return encoded_jwt


def generate_installation_jwt():
    """
    Generate the installation token for the Github API
    """
    installation_id = api_constant.gh_app_installation_id
    auth_headers = get_headers()
    auth_headers["Authorization"] = f"Bearer {generate_jwt()}"
    url = "https://api.github.com/app/installations/" f"{installation_id}/access_tokens"
    logger.info("Generating installation token")
    response = requests.post(url, headers=auth_headers, verify=get_verify_ssl())
    if response.status_code == 201:
        return response.json().get("token")
    raise ValueError("Failed to generate installation token")
