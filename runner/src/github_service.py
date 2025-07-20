"""
Module to interact with Github API for downloading and uploading files
"""
import logging
import base64
import time
import os
import yaml
import requests
import jwt
from runner.src import api_constant
from runner.src import exceptions
from runner.src.jwt_token_info import JWTTokenInfo
from runner.src.model import InputModel
from runner.src import helpers

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
    get_file_content(input_url, working_dir)

    if input_model.config_type in ["cdn", "security", "tls", "cert", "mtls", "workers"]:
        # get zone_parameters.yml file
        zone_parameters_url = (
            f"https://api.github.com/repos/{repo_name}/contents/"
            f"{input_model.environment.value}/{input_model.fqdn}/zone_parameters.yml?ref={repo_ref}"
        )
        get_file_content(zone_parameters_url, working_dir)

    if input_model.config_type in ["account", "workers"]:
        # get all workers script files
        logger.info("Downloading all worker script files")
        yaml_parameters = load_parameters_yaml(working_dir, input_model.config_type)
        js_file_list = get_workers_js_list(input_model, yaml_parameters)
        get_multiple_file_content(repo_name, repo_ref, js_file_list, working_dir)


def get_download_url(repo, path, ref):
    """
    Get the download URL for the file from Github
    """
    if repo and path and ref:
        return f"https://api.github.com/repos/{repo}/contents/{path}?ref={ref}"
    raise ValueError("Invalid input for download URL")


def get_verify_ssl():
    """
    Get the verify_ssl flag based on the environment - ONLY FOR LOCAL TESTING
    """
    verify_ssl = True
    if api_constant.local:
        verify_ssl = False
    return verify_ssl


def get_installation_id_by_url(url: str) -> str:
    """
    Get the installation ID from environment variable based on the URL

    Args
    ----
    url (str): The repository URL

    Returns
    -------
    str: The installation ID for the organization from environment variable based on the URL
    """
    if url.startswith(api_constant.GITHUB_RSTD_ORG_URL_PREFIX):
        installation_id = api_constant.gh_rstd_org_installation_id
    else:
        installation_id = api_constant.gh_app_installation_id
    return installation_id


def get_file_content(url: str, working_dir: str | None = None) -> str | None:
    """
    Get the file content from the Github API

    Args
    ----
    url (str): The URL to fetch the file content from
    working_dir (str | None): The working directory to save the file content

    Returns
    -------
    str | None: The file content. If working_dir is not provided, content is not saved to file
    """
    auth_headers = get_headers()
    installation_id = get_installation_id_by_url(url)
    auth_headers["Authorization"] = (
        f"Bearer {generate_installation_jwt(installation_id)}"
    )
    logger.info("Getting input yaml content %s", url)
    response = requests.get(
        url, headers=auth_headers, verify=get_verify_ssl(), timeout=10
    )
    if response.status_code == 200 and isinstance(response.json(), dict):
        file_content_decoded = base64.b64decode(response.json().get("content"))
        file_content = file_content_decoded.decode("utf-8")
        file_name = response.json().get("name")
        if working_dir:
            download_file_content(file_content, file_name, working_dir)
        return file_content
    logger.error("Unable to fetch the content from Github: %s", response.status_code)
    raise exceptions.GithubServiceFileFetchException(
        f"Unable to fetch the content from Github for the URL: {url}"
    )


def download_file_content(file_content, file_name, working_dir) -> None:
    """
    Download the file content to the working directory

    Args
    ----
    response_json (dict): The response JSON from the Github API
    working_dir (str): The working directory to save the file content
    """
    if os.path.exists(working_dir):
        with open(working_dir + "/" + file_name, "w", encoding="UTF-8") as file:
            file.write(file_content)
    else:
        logger.error("Directory %s does not exist", working_dir)
        raise FileNotFoundError(f"Directory {working_dir} does not exist")


def get_multiple_file_content(
    repo: str, ref: str, file_paths: list, working_dir: str
) -> None:
    """
    Get the folder content from the Github API
    """
    for file_path in file_paths:
        url = get_download_url(repo, file_path, ref)
        get_file_content(url, working_dir)


def load_parameters_yaml(cwd: str, config_type: str) -> dict:
    """
    Load the parameters yaml file for the workers config

    Args
    ----
    cwd (str): The current working directory
    config_type (str): The config type for the workers

    Returns
    -------
    dict: The parameters yaml file

    Raises
    ------
    GithubServiceException: If the parameters yaml file is not loaded
    """
    with open(f"{cwd}/{config_type}_parameters.yml", "r", encoding="utf-8") as file:
        yaml_parameters = yaml.safe_load(file)
    if not yaml_parameters:
        raise exceptions.GithubServiceException("Error loading parameters yml")
    return yaml_parameters


def get_workers_js_list(input_model: InputModel, worker_params: dict) -> list:
    """
    Get the list of JS files for the workers config

    Args
    ----
    input_model (InputModel): The input model for the request
    worker_params (list): The worker parameters for the request

    Returns
    -------
    list: The list of JS files
    """
    zone = input_model.fqdn
    env = input_model.environment.value
    config_type = input_model.config_type
    js_file_list = []
    if config_type == "account":
        js_file_prefix = env
        if (
            "noname_configs" in worker_params
            and "script_file" in worker_params["noname_configs"]
        ):
            js_file_list.append(
                f"{js_file_prefix}/{worker_params['noname_configs']['script_file']}"
            )
    elif config_type == "workers":
        js_file_prefix = f"{env}/{zone}/{config_type}"
    if "worker_configs" in worker_params:
        js_file_list.extend(
            [
                f"{js_file_prefix}/{worker_param['script_file']}"
                for worker_param in worker_params["worker_configs"]
                if "script_file" in worker_param
            ]
        )
    return js_file_list


def get_github_sha(repo: str, ref: str = "main") -> str:
    """
    Get the SHA for the Github repository

    Args
    ----
    repo (str): The repository name
    ref (str): The branch name. Default is main

    Returns
    -------
    str: The SHA for the repository

    Raises
    ------
    GithubServiceShaFetchException: If the response to fetch SHA is not 200
    """
    auth_headers = get_headers()
    url = f"https://api.github.com/repos/{repo}/commits/{ref}"
    installation_id = get_installation_id_by_url(url)
    auth_headers["Authorization"] = (
        f"Bearer {generate_installation_jwt(installation_id)}"
    )
    response = requests.get(
        url, headers=auth_headers, verify=get_verify_ssl(), timeout=10
    )
    if response.status_code == 200:
        return response.json().get("sha")
    raise exceptions.GithubServiceShaFetchException("Failed to fetch SHA from Github")


def create_github_branch(repo: str, branch_name: str, ref: str) -> dict:
    """
    Create a new branch in the Github repository

    Args
    ----
    repo (str): The repository name
    branch_name (str): The branch name

    Raises
    ------
    GithubServiceBranchCreationException: If the response to create branch is not 201
    """
    auth_headers = get_headers()
    url = f"https://api.github.com/repos/{repo}/git/refs"
    installation_id = get_installation_id_by_url(url)
    auth_headers["Authorization"] = (
        f"Bearer {generate_installation_jwt(installation_id)}"
    )
    payload = {"ref": f"refs/heads/{branch_name}", "sha": ref}
    response = requests.post(
        url, headers=auth_headers, json=payload, verify=get_verify_ssl(), timeout=10
    )
    if response.status_code == 201:
        logger.info("Branch %s created successfully", branch_name)
        return response.json()
    logger.error("Failed to create branch %s", response.text)
    raise exceptions.GithubServiceBranchCreationException(
        f"Failed to create branch {branch_name}"
    )


def create_github_pr(
    repo: str, branch_name: str, title: str, body: str, base_branch: str = "main"
) -> None:
    """
    Create a new pull request in the Github repository

    Args
    ----
    repo (str): The repository name
    branch_name (str): The branch name
    title (str): The PR title
    body (str): The PR body
    base_branch (str): The base branch. Default is main

    Raises
    ------
    GithubServicePRCreationException: If the response to create PR is not 201
    """
    auth_headers = get_headers()
    url = f"https://api.github.com/repos/{repo}/pulls"
    installation_id = get_installation_id_by_url(url)
    auth_headers["Authorization"] = (
        f"Bearer {generate_installation_jwt(installation_id)}"
    )
    payload = {"title": title, "body": body, "head": branch_name, "base": base_branch}
    response = requests.post(
        url, headers=auth_headers, json=payload, verify=get_verify_ssl(), timeout=10
    )
    if response.status_code == 422 and response.json().get("errors")[0].get(
        "message"
    ).startswith("A pull request already exists"):
        logger.error("PR already exists for branch %s", branch_name)
    elif response.status_code == 201:
        logger.info("PR created successfully for branch %s", branch_name)
    else:
        logger.error("Failed to create PR %s", response.text)
        raise exceptions.GithubServicePRCreationException(
            f"Failed to create PR for branch {branch_name}"
        )


def update_github_file(
    repo: str, branch_name: str, file_path: str, file_content: str, commit_message: str
) -> None:
    """
    Update the file content in the Github repository

    Args
    ----
    repo (str): The repository name
    branch_name (str): The branch name
    file_path (str): The file path
    file_content (str): The file content
    commit_message (str): The commit message

    Raises
    ------
    GithubServiceFileUpdateException: If the response to update file is not 200
    """
    auth_headers = get_headers()
    url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
    installation_id = get_installation_id_by_url(url)
    auth_headers["Authorization"] = (
        f"Bearer {generate_installation_jwt(installation_id)}"
    )
    file_sha_response = requests.get(
        f"{url}?ref={branch_name}",
        headers=auth_headers,
        verify=get_verify_ssl(),
        timeout=10,
    )
    if file_sha_response.status_code != 200:
        logger.error("Failed to fetch file %s", file_sha_response.text)
        raise exceptions.GithubServiceFileFetchException(
            f"Failed to fetch file {file_path}"
        )
    payload = {
        "message": commit_message,
        "content": base64.b64encode(file_content.encode()).decode(),
        "sha": file_sha_response.json().get("sha"),
        "branch": branch_name,
        "committer": {
            "name": api_constant.GITHUB_COMMITTER_NAME,
            "email": api_constant.GITHUB_COMMITTER_EMAIL,
        },
    }
    response = requests.put(
        url, headers=auth_headers, json=payload, verify=get_verify_ssl(), timeout=10
    )
    if response.status_code == 200:
        logger.info("File %s updated successfully", file_path)
        return response.json()
    logger.error("Failed to update file %s", response.text)
    raise exceptions.GithubServiceFileUpdateException(
        f"Failed to update file {file_path}"
    )


def get_repo_branch(repo: str, branch_name: str) -> dict:
    """
    Get the branch details from the Github repository

    Args
    ----
    repo (str): The repository name
    branch_name (str): The branch name

    Returns
    -------
    dict: The branch details if found, else empty dict
    """
    auth_headers = get_headers()
    url = f"https://api.github.com/repos/{repo}/branches/{branch_name}"
    installation_id = get_installation_id_by_url(url)
    auth_headers["Authorization"] = (
        f"Bearer {generate_installation_jwt(installation_id)}"
    )
    response = requests.get(
        url, headers=auth_headers, verify=get_verify_ssl(), timeout=10
    )
    if response.status_code == 200:
        return response.json()
    raise exceptions.GithubServiceBranchNotFoundException(
        f"Branch {branch_name} not found in the repository {repo}"
    )


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


def generate_installation_jwt(installation_id: str):
    """
    Generate the installation token for the Github API
    """
    if not installation_id:
        raise exceptions.GithubServiceException("Installation id is empty")
    auth_headers = get_headers()
    auth_headers["Authorization"] = f"Bearer {generate_jwt()}"
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    logger.info("Generating installation token")
    response = requests.post(
        url, headers=auth_headers, verify=get_verify_ssl(), timeout=10
    )
    if response.status_code == 201:
        gh_bearer_token = response.json().get("token")
        return gh_bearer_token
    raise ValueError("Failed to generate installation token")
