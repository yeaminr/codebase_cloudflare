import subprocess
import os
import logging
from runner.src import exceptions
from runner.src import working_dir as wd
from runner.src import cloudflare_token_service
from runner.src import api_constant
from runner.src.model import InputModel

logger = logging.getLogger(__name__)

def create_backend_file(working_directory: str, state_key: str) -> None:
    """
    Creates a backend.tf configuration file for Terraform.

    Args:
        working_directory (str): The path to the Terraform working directory.
        state_key (str): The key to use for the state file in the S3 bucket.

    Returns:
        None
    """
    bucket_name = api_constant.state_bucket_name
    dynamodb_table = api_constant.state_lock_dynamodb_table
    if not bucket_name:
        logger.error("TF_STATE_BUCKET_NAME environment variable is not set")
        raise exceptions.TerraformServiceBackendException(
            "TF_STATE_BUCKET_NAME environment variable is not set"
        )
    if not dynamodb_table:
        logger.error(
            "TF_STATE_LOCK_DYNAMODB_TABLE environment variable is not set")
        raise exceptions.TerraformServiceBackendException(
            "TF_STATE_LOCK_DYNAMODB_TABLE environment variable is not set"
        )
    if not state_key:
        logger.error("State key is not set")
        raise exceptions.TerraformServiceBackendException(
            "State key is not set")
    backend_config = api_constant.BACKEND_TEMPLATE.format(
        bucket=bucket_name,
        key=state_key,
        dynamodb_table=dynamodb_table,
    )
    logger.info("Backend config: %s", backend_config)
    with open(
        os.path.join(working_directory, "backend.tf"), "w", encoding="UTF-8"
    ) as file:
        file.write(backend_config)


def get_backend_key(zone_name: str, config_type: str) -> str:
    """
    Creates the backend key from the input_vars_path.
    Get the zone name and use it to create the backend key.

    Args:
        input_vars_path (str): The path to the input variables file.

    Returns:
        str: The backend key to use for the state file in the S3 bucket.
    """
    state_key = None
    if config_type == "account":
        return api_constant.STATE_FILE_SUFFIX_MAP["account"]
    for suffix, key in api_constant.STATE_FILE_SUFFIX_MAP.items():
        if config_type == suffix:
            state_key = f"{zone_name}/{key}"
            break
    if state_key is None:
        logger.error(
            "Error in creating backend key for Config Type : %s, Zone Name : %s",
            config_type,
            zone_name,
        )
        raise exceptions.TerraformServiceBackendException(
            f"Error in creating backend key for Config Type : {config_type}, Zone Name : {zone_name}"
        )

    return state_key


def run_terraform_command(command: str, working_directory: str):
    """
    Runs a Terraform command in the specified working directory.

    Args
    ----
    command (str): The Terraform command to run e.g. init, plan, apply
    working_directory (str): The working directory to run the Terraform command

    Returns
    -------
    tuple: A tuple containing the return code, stdout, and stderr of the command
    """
    with subprocess.Popen(
        command,
        cwd=working_directory,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=True,
    ) as process:
        stdout, stderr = process.communicate()
        return process.returncode, stdout.decode(), stderr.decode()


def terraform_init(working_directory: str, zone: str, config_type: str):
    """
    Initializes the Terraform configuration using the terraform init command
    """
    command = ["terraform", "init", "-input=false"]
    if not api_constant.local:
        backend_state_key = get_backend_key(zone, config_type)
        logger.info("Backend state key: %s", backend_state_key)
        create_backend_file(working_directory, backend_state_key)
    command_str = " ".join(command)
    logger.info("Running Terraform init command: %s", command_str)
    return run_terraform_command(command_str, working_directory)


def terraform_plan(working_directory: str, account_id: str):
    """
    Creates an execution plan for Terraform using the terraform plan command
    """
    # use -no-color tag to remove ANSI color codes from the output
    command = ["terraform", "plan", "-no-color",
               f"-var=account_id={account_id}"]
    command_str = " ".join(command)
    logger.info("Running Terraform plan command: %s", command_str)
    return run_terraform_command(command_str, working_directory)


def terraform_apply(working_directory, account_id: str):
    """
    Applies the Terraform configuration using the terraform apply command
    """
    # use -no-color tag to remove ANSI color codes from the output
    command = [
        "terraform",
        "apply",
        "-auto-approve",
        "-no-color",
        f"-var=account_id={account_id}"
    ]
    command_str = " ".join(command)
    return run_terraform_command(command_str, working_directory)


def terraform_output(working_directory: str, name: str = None):
    """
    Retrieves the output value(s) from Terraform.

    Args:
        working_directory (str): The path to the Terraform working directory.
        name (str, optional): The specific output name to retrieve. Defaults to None.

    Returns:
        str: The output value(s) from Terraform.

    """
    command = ["terraform", "output"]
    if name:
        command.append("-raw")
        command.append(name)
    command_str = " ".join(command)
    logger.info("Running Terraform output command: %s", command_str)
    return run_terraform_command(command_str, working_directory)


def run(input_model: InputModel, working_dir: str):
    """
    Orchestrates the Terraform process by running the
    Terraform init, plan, or apply commands based on the payload.

    Args:
        environment (str): The environment to deploy to. e.g. dev, test, prod
        zone (str): The zone to deploy to. e.g. example.com
        config_type (str): The type of config. e.g. account, zone, cdn, security, tls
        working_dir (str): The path to the working directory.
        action (str): The action to perform. e.g. plan, apply

    Returns:
        str: The output from the Terraform command.
    """
    logger.info("Initializing Terraform")
    codebase_path = f"cf/terraform/{input_model.config_type.lower()}"
    wd.copy_tf_files(codebase_path, working_dir)

    returncode, stdout, stderr = terraform_init(
        working_dir, input_model.fqdn, input_model.config_type)
    if returncode != 0:
        logger.error("Error initializing Terraform: %s", stderr)
        raise exceptions.TerraformServiceOperationException(
            f"Error initializing Terraform: {stderr}"
        )

    logger.info("Terraform init output: %s", stdout)

    try:
        token_store = cloudflare_token_service.set_cloudflare_scoped_token(input_model)
    except exceptions.TokenServiceException as e:
        logger.error("Error setting Cloudflare scoped token: %s", e)
        raise exceptions.TerraformServiceOperationException(
            f"Error setting Cloudflare scoped token: {e}"
        )
    try:
        if input_model.action == "plan":
            returncode, stdout, stderr = terraform_plan(
                working_dir, input_model.account_id)
            if returncode != 0:
                logger.error(
                    "Error during Terraform plan: %s - %s - %s", returncode, stdout, stderr
                )
                raise exceptions.TerraformServiceOperationException(stderr)
        elif input_model.action == "apply":
            returncode, stdout, stderr = terraform_apply(
                working_dir, input_model.account_id)
            if returncode != 0:
                logger.error(
                    "Error during Terraform apply: %s - %s - %s", returncode, stdout, stderr
                )
                raise exceptions.TerraformServiceOperationException(
                    f"Error during Terraform apply: {stderr}"
                )

        logger.info("Terraform output: %s", stdout)
        return stdout
    except Exception as e:
        raise e
    finally:
        deleted_tokens = cloudflare_token_service.delete_all_tokens(
            api_constant.cf_initial_api_token, token_store
        )
        remaining = list(set(token_store) - set(deleted_tokens))
        logger.info("Cloudflare active scoped tokens: %s", remaining)
