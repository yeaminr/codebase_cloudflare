"""
Module to handle Terraform operations such as init, plan, and apply.
"""

import subprocess
import os
import logging
from runner.src import helpers
from runner.src import exceptions
from runner.src import working_dir as wd
from runner.src import cloudflare_token_service
from runner.src import api_constant
from runner.src.model import InputModel
import re

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
        logger.error("TF_STATE_LOCK_DYNAMODB_TABLE environment variable is not set")
        raise exceptions.TerraformServiceBackendException(
            "TF_STATE_LOCK_DYNAMODB_TABLE environment variable is not set"
        )
    if not state_key:
        logger.error("State key is not set")
        raise exceptions.TerraformServiceBackendException("State key is not set")
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


def run_terraform_command(
    command: str, working_directory: str, cloudflare_scoped_token: str = None
) -> tuple:
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
        env={
            **os.environ,
            **(
                {"CLOUDFLARE_API_TOKEN": cloudflare_scoped_token}
                if cloudflare_scoped_token
                else {}
            ),
        },
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


def terraform_init_reconfigure(working_directory: str, zone: str, config_type: str):
    """
    Initializes the Terraform configuration using the terraform init -reconfigure command
    """
    command = ["terraform", "init", "-input=false", "-reconfigure"]
    if not api_constant.local:
        backend_state_key = get_backend_key(zone, config_type)
        logger.info("Backend state key: %s", backend_state_key)
        create_backend_file(working_directory, backend_state_key)
    command_str = " ".join(command)
    logger.info("Running Terraform init -reconfigure command: %s", command_str)
    return run_terraform_command(command_str, working_directory)


def terraform_plan(
    working_directory: str, account_id: str, cloudflare_scoped_token: str
):
    """
    Creates an execution plan for Terraform using the terraform plan command
    """
    # use -no-color tag to remove ANSI color codes from the output
    command = [
        "terraform",
        "plan",
        "-no-color",
        f"-var=account_id={account_id}",
        "-compact-warnings",
    ]
    command_str = " ".join(command)
    logger.info("Running Terraform plan command: %s", command_str)
    return run_terraform_command(
        command_str, working_directory, cloudflare_scoped_token
    )


def terraform_apply(working_directory, account_id: str, cloudflare_scoped_token: str):
    """
    Applies the Terraform configuration using the terraform apply command
    """
    # use -no-color tag to remove ANSI color codes from the output
    command = [
        "terraform",
        "apply",
        "-auto-approve",
        "-no-color",
        f"-var=account_id={account_id}",
        "-compact-warnings",
    ]
    command_str = " ".join(command)
    return run_terraform_command(
        command_str, working_directory, cloudflare_scoped_token
    )


def terraform_output(working_directory: str, name: str = None, format_flag: str = None):
    """
    Retrieves the output value(s) from Terraform.

    Args:
        working_directory (str): The path to the Terraform working directory.
        name (str, optional): The specific output name to retrieve. Defaults to None.
        format_flag (str, optional): The format flag to use. Defaults to None.

    Returns:
        str: The output value(s) from Terraform.

    """
    command = ["terraform", "output"]
    if format_flag and format_flag in ["-json", "-raw"]:
        command.append(format_flag)
    if name:
        command.append(name)
    command_str = " ".join(command)
    logger.info("Running Terraform output command: %s", command_str)
    return run_terraform_command(command_str, working_directory)


def terraform_state_list(
    working_directory: str, resource_id: str, cloudflare_scoped_token: str
):
    """
    Run terraform state list command on a resource id
    """
    command = ["terraform", "state", "list", f"-id={resource_id}"]
    command_str = " ".join(command)
    logger.info("Running terraform state list command: %s", command_str)
    return run_terraform_command(
        command_str, working_directory, cloudflare_scoped_token
    )


def cf_terraforming_import(
    cwd: str, resource_type: str, zone_id: str, cloudflare_scoped_token: str
):
    """
    Run the cf-terraforming import command

    Args:
        cwd (str): The current working directory where the import command will be run.
        resource_type (str): The type of Cloudflare resource to import.
        zone_id (str): The ID of the Cloudflare zone to import resources from.
        cloudflare_scoped_token (str): The scoped token for Cloudflare API access.
    """
    command = [
        "cf-terraforming",
        "import",
        f"--terraform-binary-path {api_constant.TERRAFORM_BINARY_PATH}",
        f"--resource-type {resource_type}",
        f"--zone {zone_id}",
    ]
    command_str = " ".join(command)
    logger.info("Running cf-terraforming import command: %s", command_str)
    return run_terraform_command(command_str, cwd, cloudflare_scoped_token)


def cf_terraforming_generate(
    cwd: str, resource_type: str, zone_id: str, cloudflare_scoped_token: str
):
    """
    Run the cf-terraforming generate command

    Args:
        cwd (str): The current working directory where the import command will be run.
        resource_type (str): The type of Cloudflare resource to import.
        zone_id (str): The ID of the Cloudflare zone to import resources from.
        cloudflare_scoped_token (str): The scoped token for Cloudflare API access.
    """
    command = [
        "cf-terraforming",
        "generate",
        f"--terraform-binary-path {api_constant.TERRAFORM_BINARY_PATH}",
        f"-z {zone_id}",
        f"--resource-type {resource_type}",
    ]
    command_str = " ".join(command)
    logger.info("Running cf-terraforming generate command: %s", command_str)
    return run_terraform_command(command_str, cwd, cloudflare_scoped_token)


def run(input_model: InputModel, working_dir: str):
    """
    Orchestrates the Terraform process by running the
    Terraform init, plan, or apply commands based on the payload.

    Args:
        environment (str): The environment to deploy to. e.g. dev, test, prod
        zone (str): The zone to deploy to. e.g. example.com
        config_type (str): The type of config. e.g. account, zone, cdn, security, tls, mtls
        working_dir (str): The path to the working directory.
        action (str): The action to perform. e.g. plan, apply

    Returns:
        str: The output from the Terraform command.
    """
    logger.info("Initializing Terraform")
    codebase_path = f"cf/terraform/{input_model.config_type.lower()}"
    wd.copy_tf_files(codebase_path, working_dir)

    returncode, stdout, stderr = terraform_init(
        working_dir, input_model.fqdn, input_model.config_type
    )
    if returncode != 0:
        logger.error("Error initializing Terraform: %s", stderr)
        raise exceptions.TerraformServiceOperationException(
            f"Error initializing Terraform: {stderr}"
        )

    logger.info("Terraform init output: %s", stdout)

    try:
        token_store, cloudflare_scoped_token = (
            cloudflare_token_service.set_cloudflare_scoped_token(input_model)
        )
    except exceptions.TokenServiceException as e:
        logger.error("Error setting Cloudflare scoped token: %s", e)
        raise exceptions.TerraformServiceOperationException(
            f"Error setting Cloudflare scoped token: {e}"
        )
    try:
        if input_model.action == "plan":
            returncode, stdout, stderr = terraform_plan(
                working_dir, input_model.account_id, cloudflare_scoped_token
            )
            if returncode != 0:
                logger.error(
                    "Error during Terraform plan: %s - %s - %s",
                    returncode,
                    stdout,
                    stderr,
                )
                raise exceptions.TerraformServiceOperationException(stderr)
        elif input_model.action == "apply":
            returncode, stdout, stderr = terraform_apply(
                working_dir, input_model.account_id, cloudflare_scoped_token
            )
            if returncode != 0:
                logger.error(
                    "Error during Terraform apply: %s - %s - %s",
                    returncode,
                    stdout,
                    stderr,
                )
                raise exceptions.TerraformServiceOperationException(
                    f"Error during Terraform apply: {stderr}"
                )
        logger.info("Terraform output: %s", stdout)
        return stdout
    except Exception as e:
        logger.info("Error in Terraform operation: %s", e)
        raise e
    finally:
        cf_initial_api_token = helpers.check_initial_token(input_model.environment)
        deleted_tokens = cloudflare_token_service.delete_all_tokens(
            cf_initial_api_token, token_store
        )
        remaining = list(set(token_store) - set(deleted_tokens))
        logger.info("Cloudflare active scoped tokens: %s", remaining)


def create_providers_file(cwd: str) -> None:
    """
    Creates a providers.tf file with the Cloudflare provider configuration.
    This is necessary for Terraform to know which provider to use.

    Args:
        cwd (str): The current working directory where the providers.tf file will be created.
    """
    logger.info("Creating providers.tf file in %s", cwd)
    providers_content = api_constant.TERRAFORM_PROVIDER_TEMPLATE
    providers_file_path = f"{cwd}/providers.tf"
    with open(providers_file_path, "w", encoding="UTF-8") as file:
        file.write(providers_content)


def run_cf_terraforming(
    input_model: InputModel, resource_type: str
) -> tuple[str, list, str]:
    """
    Runs the cf-terraforming command to import Cloudflare resources into Terraform.
    This will help identify any new resources that exist outside of Terraform state
    This will not take any actions on the resources, it will provide guidance on which resources need to be added in

    Args:
        input_model (InputModel): The input model containing the necessary parameters.
        resource_type (str): The type of Cloudflare resource to import.

    Returns:
        tuple: output from the import command, list of new resource IDs, and any generated configuration.
    """
    logger.info(
        "Running cf-terraforming import check for resource type %s in zone %s",
        resource_type,
        input_model.fqdn,
    )
    # validate the resource type against the pattern
    pattern = re.compile(api_constant.CLOUDFLARE_RESOURCE_TYPE_PATTERN)
    if not pattern.match(resource_type):
        logger.error("Invalid resource type: %s", resource_type)
        raise exceptions.CfTerraformingException(
            f"Invalid resource type: {resource_type}"
        )

    cwd = wd.create_dir()
    try:
        token_store, cloudflare_scoped_token = (
            cloudflare_token_service.set_cloudflare_scoped_token(input_model)
        )
    except exceptions.TokenServiceException as e:
        logger.error("Error setting Cloudflare scoped token: %s", e)
        raise exceptions.TerraformServiceOperationException(
            f"Error setting Cloudflare scoped token: {e}"
        )

    try:
        # Get the zone id
        zone_id = helpers.get_zone_id(input_model.fqdn, cloudflare_scoped_token)

        # create providers.tf file
        create_providers_file(cwd)

        # run first terraform init to ensure the backend is set up correctly
        logger.info("Running first Terraform init")
        returncode, init_stdout, init_stderr = terraform_init(
            cwd, input_model.fqdn, "zone"
        )
        if returncode != 0:
            logger.error("Error initializing Terraform: %s", init_stderr)
            raise exceptions.TerraformServiceOperationException(
                f"Error initializing Terraform: {init_stderr}"
            )

        logger.info("Terraform init output: %s", init_stdout)

        # run cf-terraforming import command on the resource type
        returncode, import_stdout, import_stderr = cf_terraforming_import(
            cwd, resource_type, zone_id, cloudflare_scoped_token
        )
        if returncode != 0:
            logger.error("Error running cf-terraforming import: %s", import_stderr)
            raise exceptions.CfTerraformingException(
                f"Error running cf-terraforming import: {import_stderr}"
            )

        logger.info("cf-terraforming import output: %s", import_stdout)

        # Parse the output to find new resources
        new_resource_ids = []
        for line in import_stdout.splitlines():
            if "terraform import" not in line:
                logger.info("Unexpected terraform import format: %s", line)
                continue

            # Extract the resource type and ID from the line
            # expected format: terraform import <resource_type>.<resource_name> <full_resource_id>
            parts = line.split()
            if len(parts) < 4:
                logger.info("Unexpected terraform import format: %s", line)
                continue

            full_resource_id = parts[
                -1
            ]  # The last part is the full resource ID. <zone_id>/<resource_id>
            resource_id: str = full_resource_id.split("/")[
                -1
            ]  # Extract the last part after the slash
            logger.info("Resource ID: %s", resource_id)

            # check resource id is sensible
            if not all(c.isalnum() or c == '-' for c in resource_id):
                logger.info(
                    "Unexpected resource id from cf-terraforming: %s", resource_id
                )
                continue

            allowed_configs = api_constant.TENANT_ALLOWED_CONFIGS
            found = False
            for config in allowed_configs:
                logger.info(
                    "Checking resource ID %s in config %s", resource_id, config)
                # point backend to state file
                returncode, init_stdout, init_stderr = terraform_init_reconfigure(
                    cwd, input_model.fqdn, config
                )
                if returncode != 0:
                    logger.error("Error initializing Terraform: %s", init_stderr)
                    raise exceptions.TerraformServiceOperationException(
                        f"Error initializing Terraform: {init_stderr}"
                    )

                logger.info("Terraform init output: %s", init_stdout)

                # run the state list command to check if the resource is in state
                returncode, state_stdout, state_stderr = terraform_state_list(
                    cwd, resource_id, cloudflare_scoped_token
                )

                if returncode != 0:
                    logger.error("Error running terraform state: %s", state_stderr)
                    if "no state file was found" in state_stderr.lower():
                        # state file does not exist
                        continue

                    raise exceptions.TerraformServiceOperationException(
                        f"Error running terraform state: {state_stderr}"
                    )
                logger.info("Terraform state output: %s", state_stdout)

                if state_stdout:
                    # state command output is not empty, resource is in state
                    found = True
                    break

            # if the resource is not found in any of the state files, we can add it
            if not found:
                new_resource_ids.append(resource_id)

        # no new resources found
        if not new_resource_ids:
            logger.info("No new resource IDs found")
            return import_stdout, new_resource_ids, ""

        # new resources found, generate the Terraform configuration for them
        logger.info("New Resource IDs: %s", new_resource_ids)
        returncode, generate_stdout, generate_stderr = cf_terraforming_generate(
            cwd, resource_type, zone_id, cloudflare_scoped_token
        )
        if returncode != 0:
            logger.error("Error running cf-terraforming generate: %s", generate_stderr)
            raise exceptions.CfTerraformingException(
                f"Error running cf-terraforming generate: {generate_stderr}"
            )

        logger.info("cf-terraforming generate output: %s", generate_stdout)

        return import_stdout, new_resource_ids, generate_stdout
    except Exception as e:
        logger.error("Error in cf-terraforming: %s", e)
        raise e from e
    finally:
        cf_initial_api_token = helpers.check_initial_token(input_model.environment)
        deleted_tokens = cloudflare_token_service.delete_all_tokens(
            cf_initial_api_token, token_store
        )
        remaining = list(set(token_store) - set(deleted_tokens))
        logger.info("Cloudflare active scoped tokens: %s", remaining)
        wd.delete_dir(cwd)


def cf_terraforming(input_model: InputModel, resource_type: str) -> dict:
    """
    Entry function for cf_terraforming to run provided resource types

    Args:
        input_model (InputModel): The input model containing the necessary parameters.
        resource_type (str): The type of Cloudflare resource to import.

    Returns:
        dict: A dictionary containing the import output, new resource IDs, and generated configuration
                for each resource type
    """
    if resource_type == "all":
        types = api_constant.CF_TERRAFORMING_RESOURCES
    else:
        types = [resource_type]

    return_obj = {}
    for resource in types:
        import_stdout, new_resource_ids, generate_stdout = run_cf_terraforming(
            input_model, resource
        )
        return_obj[resource] = {
            "import_output": import_stdout,
            "new_resources": new_resource_ids,
            "generate_output": generate_stdout,
        }
    return return_obj
