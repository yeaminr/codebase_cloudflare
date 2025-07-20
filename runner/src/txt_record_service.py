"""
Module to process TXT records for Bankwest and CBA domains.
"""
import logging
import yaml
from runner.src import aws_service
from runner.src import github_service
from runner.src import api_constant
from runner.src.model import InputModel
from runner.src import exceptions

logger = logging.getLogger(__name__)


def process_txt_record(model: InputModel, txt_record_name: str, txt_record_value: str, cwd: str = None):
    """
    Process the TXT record based on the domain.
    If the domain is any of the valid BANKWEST_DOMAINS, then process the Bankwest TXT record.
    Otherwise, process the AWS TXT record which is for all other CBA domains.

    Args:
        model (InputModel): The input model.
        txt_record_name (str): The TXT record name.
        txt_record_value (str): The TXT record value.
        cwd (str): The current working directory. Optional, used for getting dns_env from zone parameters.yml.
    """
    if any(bw_domain in model.fqdn for bw_domain in api_constant.BANKWEST_DOMAINS):
        logger.info("Processing Bankwest TXT record.")
        process_bankwest_txt_record(model, txt_record_value)
    else:
        logger.info("Processing CBA TXT record.")
        aws_service.process_txt_record(model, txt_record_name, txt_record_value, cwd)


def process_bankwest_txt_record(model: InputModel, txt_record_value: str):
    """
    Process the Bankwest TXT record.
    Get the updated YAML content for the TXT record.
    Check branch exists, if not create a branch.
    Check if the file content is different from the updated YAML content.
    Update the file content if different otherwise do nothing.
    Create a PR for the feature branch if the file content is updated.
    """
    updated_yaml_content, file_path = updated_fqdn_yaml_content(
        model.fqdn, txt_record_value
    )
    if not updated_yaml_content or not file_path:
        logger.info("TXT record already available for fqdn %s", model.fqdn)
        return
    main_branch_sha = github_service.get_github_sha(
        api_constant.BANKWEST_DNS_RECORD_REPO,
        api_constant.BANKWEST_DNS_RECORD_REPO_BRANCH,
    )
    feature_branch = f"feature/{model.change_number}-{model.fqdn}"
    try:
        github_service.get_repo_branch(
            api_constant.BANKWEST_DNS_RECORD_REPO, feature_branch
        )
        logger.warning("Branch %s already exists.", feature_branch)
    except exceptions.GithubServiceBranchNotFoundException:
        github_service.create_github_branch(
            api_constant.BANKWEST_DNS_RECORD_REPO,
            feature_branch,
            main_branch_sha,
        )
        logger.info("Branch %s created.", feature_branch)
    feature_branch_file_url = github_service.get_download_url(
        api_constant.BANKWEST_DNS_RECORD_REPO,
        file_path,
        feature_branch,
    )
    updated_yaml_content_dict = yaml.safe_load(updated_yaml_content)
    feature_branch_file_url_dict = yaml.safe_load(
        github_service.get_file_content(feature_branch_file_url)
    )
    if updated_yaml_content_dict != feature_branch_file_url_dict:
        logger.info("Updating %s with the new TXT record.", file_path)
        github_service.update_github_file(
            api_constant.BANKWEST_DNS_RECORD_REPO,
            feature_branch,
            file_path,
            updated_yaml_content,
            api_constant.BANKWEST_COMMIT_MESSAGE.format(
                change_number=model.change_number, fqdn=model.fqdn
            ),
        )
    else:
        logger.info(
            "TXT %s record already available for fqdn %s", txt_record_value, model.fqdn
        )
    github_service.create_github_pr(
        api_constant.BANKWEST_DNS_RECORD_REPO,
        feature_branch,
        api_constant.BANKWEST_COMMIT_MESSAGE.format(
            change_number=model.change_number, fqdn=model.fqdn
        ),
        api_constant.BANKWEST_PULL_REQUEST_TEMPLATE.format(
            txt_record_value=txt_record_value,
            fqdn=model.fqdn,
            change_number=model.change_number,
        ),
        api_constant.BANKWEST_DNS_RECORD_REPO_BRANCH,
    )


def updated_fqdn_yaml_content(full_fqdn: str, txt_record_value: str) -> tuple:
    """
    Update the YAML content.
    Check if the YAML file exists for the given FQDN.
    If the file exists, check if the NS record exists.
    If the NS record exists, check if the TXT record exists.
    If the TXT record exists, do nothing.
    If the TXT record does not exist, add the record.
    If the NS record does not exist, raise an exception.
    If the file does not exist, check the next parent domain until the apex domain.
    If the apex domain does not exist, raise an exception.

    Args:
        full_fqdn (str): The full FQDN.
        txt_record_value (str): The TXT record value.

    Returns:
        tuple: The updated YAML content and the file path.

    Raises:
        TextRecordServiceException: If file not found for the given FQDN or NS record not found.
    """
    domain_parts = full_fqdn.split(".")
    for i in range(len(domain_parts) - 2):
        updated_fqdn = ".".join(domain_parts[i:])
        logger.info("Checking for %s.yaml in the repository.", updated_fqdn)
        file_url = github_service.get_download_url(
            api_constant.BANKWEST_DNS_RECORD_REPO,
            f"{api_constant.BANKWEST_DNS_RECORD_REPO_PATH}/{updated_fqdn}.yaml",
            api_constant.BANKWEST_DNS_RECORD_REPO_BRANCH,
        )
        file_content = None
        try:
            file_content = github_service.get_file_content(file_url)
        except exceptions.GithubServiceFileFetchException:
            logger.info("File %s.yaml not found in the repository.", updated_fqdn)
            continue
        yaml_content = yaml.safe_load(file_content)
        ns_record_exist = check_ns_record_exists(yaml_content)
        txt_record_yaml = get_txt_record_name_for_yaml(full_fqdn, updated_fqdn)
        logger.info("TXT record name in YAML: %s", txt_record_yaml)
        if ns_record_exist:
            logger.info("NS Record exists for %s. Checking TXT record.", updated_fqdn)
            txt_record_exist = check_txt_record_exists(
                yaml_content,
                txt_record_yaml,
            )
            if txt_record_exist:
                logger.info("TXT Record exists for %s. Do nothing.", updated_fqdn)
                return None, None
            logger.warning(
                "Record does not exist for %s. Adding the record.", updated_fqdn
            )
            updated_yaml_content = update_txt_record_yaml(
                file_content, txt_record_yaml, txt_record_value
            )
            file_path = (
                f"{api_constant.BANKWEST_DNS_RECORD_REPO_PATH}/{updated_fqdn}.yaml"
            )
            return updated_yaml_content, file_path
        logger.warning("Record does not exist for %s", updated_fqdn)
    raise exceptions.TextRecordServiceException(
        f"Record not found for {full_fqdn}. Please check the domain name."
    )


def update_txt_record_yaml(
    file_content: str,
    txt_record_name: str,
    txt_record_value: str,
    txt_record_type: str = "TXT",
    txt_record_ttl: int = 300,
) -> str:
    """
    Update the Bankwest TXT record using string manipulation not using YAML library.
    Using YAML library will update the file content in a different format and cause big diffs.

    Args:
        file_content (str): The file content.
        txt_record_name (str): The TXT record name.
        txt_record_value (str): The TXT record value.
        txt_record_type (str): The TXT record type.
        txt_record_ttl (int): The TXT record TTL.

    Returns:
        str: The updated file content.
    """
    yaml_content = api_constant.BANKWEST_TXT_RECORD_YML_CONTENT.format(
        txt_record_name=txt_record_name,
        txt_record_type=txt_record_type,
        txt_record_value=txt_record_value,
        txt_record_ttl=txt_record_ttl,
    )
    logger.info("Updated YAML content: %s", yaml_content)
    file_content += yaml_content
    return file_content


def get_txt_record_name_for_yaml(fqdn: str, file_name_without_yaml: str):
    """
    Get the TXT record name key for the given FQDN.
    For example, if the TXT record to be added is for cloudflare-verify.bankwest.com.au,
    in the YAML file with name bankwest.com.au, then the key should be cloudflare-verify
    If the TXT record to be added is for cloudflare-verify.uat.bankwest.com.au,
    in the YAML file with name bankwest.com.au, then the key should be cloudflare-verify.uat
    In general the key should be less the file name without .yaml
    """
    if fqdn == file_name_without_yaml:
        return "cloudflare-verify"
    return f"cloudflare-verify.{fqdn.replace('.'+file_name_without_yaml, '')}"


def check_ns_record_exists(yaml_content: dict):
    """
    Check Root NS record exists for the given record name, type and value.

    Args:
        yaml_content (dict): YAML content.
        record_name (str): Record name.
        record_type (str): Record type.
        record_value (str): Record value.

    Returns:
        bool: True if NS record exists, False otherwise.
    """
    for key, obj in yaml_content.items():
        logger.info("Checking for NS record in %s", key)
        if not key:
            for item in obj:
                if item.get("type") == "NS":
                    logger.info("NS Record exists for %s", key)
                    return True
    return False


def check_txt_record_exists(yaml_content: dict, record_name: str):
    """
    Check TXT record exists for the given record name, type and value.

    Args:
        yaml_content (dict): YAML content.
        record_name (str): Record name.
        record_type (str): Record type.
        record_value (str): Record value.

    Returns:
        bool: True if TXT record exists, False otherwise.
    """
    for key, obj in yaml_content.items():
        if key == record_name and obj.get("type") == "TXT":
            return True
    return False
