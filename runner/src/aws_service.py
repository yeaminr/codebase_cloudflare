import boto3
import os
import logging
from runner.src import exceptions
from runner.src import api_constant

logger = logging.getLogger(__name__)

dev_client = boto3.client(
    "route53",
    verify=not os.environ.get("LOCAL", False),
    aws_access_key_id=api_constant.dev_txt_aws_access_key_id,
    aws_secret_access_key=api_constant.dev_txt_aws_secret_access_key,
)
prod_client = boto3.client(
    "route53",
    verify=not os.environ.get("LOCAL", False),
    aws_access_key_id=api_constant.prod_txt_aws_access_key_id,
    aws_secret_access_key=api_constant.prod_txt_aws_secret_access_key,
)


def change_resource_record_sets(
    env,
    hosted_zone_id,
    record_name,
    record_value,
    record_type="TXT",
    ttl=300,
    action="CREATE",
):
    """
    Change the resource record sets in the hosted zone.

    Args:
        env (str): The environment.
        hosted_zone_id (str): The hosted zone ID.
        record_name (str): The record name.
        record_value (str): The record value.
        record_type (str): The record type. Default is TXT.
        ttl (int): The time to live. Default is 300.
        action (str): The action. Default is CREATE.

    Returns:
        bool: True if the record is successfully updated, otherwise False.

    Raises:
        AWSServiceRoute53ChangeResourceRecordSetsException: If there is an error while updating the record.
    """
    logger.info(
        "hosted_zone_id %s record_name %s record_value %s env %s",
        hosted_zone_id,
        record_name,
        record_value,
        env,
    )
    if env == "prod":
        client = prod_client
    else:
        client = dev_client
    try:
        response = client.change_resource_record_sets(
            HostedZoneId=hosted_zone_id,
            ChangeBatch={
                "Comment": f"Added or updated {record_name} with value {record_value}",
                "Changes": [
                    {
                        "Action": action,
                        "ResourceRecordSet": {
                            "Name": record_name,
                            "Type": record_type,
                            "TTL": ttl,
                            "ResourceRecords": [{"Value": f'"{record_value}"'}],
                        },
                    }
                ],
            },
        )
    except Exception as e:
        raise exceptions.AWSServiceRoute53ChangeResourceRecordSetsException(
            f"Failed to update Route53 record for the {record_name} with value {record_value}: {e}"
        )
    if (
        "ResponseMetadata" in response
        and "HTTPStatusCode" in response["ResponseMetadata"]
        and response["ResponseMetadata"]["HTTPStatusCode"] == 200
    ):
        logger.info("Successfully updated Route53 record %s", response)
        return True
    return False


def get_hosted_zone_id_by_domain(domain, env):
    """
    Get the hosted zone ID by domain name.

    Args:
        domain (str): The domain name.
        env (str): The environment.

    Returns:
        str: The hosted zone ID if found, otherwise None.
    """
    if env == "prod":
        client = prod_client
    else:
        client = dev_client
    response = client.list_hosted_zones_by_name(DNSName=domain, MaxItems="1")
    if "HostedZones" in response:
        for hosted_zone in response["HostedZones"]:
            if "Name" in hosted_zone and hosted_zone["Name"] == f"{domain}.":
                return hosted_zone["Id"]
    return None


def check_record_exist(hosted_zone_id, record_name, record_type, env):
    """
    Check if the record exists in the hosted zone.

    Args:
        hosted_zone_id (str): The hosted zone ID.
        record_name (str): The record name.
        record_type (str): The record type.
        env (str): The environment.

    Returns:
        bool: True if the record exists, otherwise False.
    """
    if env == "prod":
        client = prod_client
    else:
        client = dev_client
    paginator = client.get_paginator("list_resource_record_sets")
    page_iterator = paginator.paginate(HostedZoneId=hosted_zone_id)
    for page in page_iterator:
        if "ResourceRecordSets" in page:
            for record_set in page["ResourceRecordSets"]:
                if (
                    record_set["Name"] == f"{record_name}."
                    and record_set["Type"] == record_type
                ):
                    logger.info(
                        "%s record found for %s : %s",
                        record_type,
                        record_name,
                        record_set,
                    )
                    return True
    return False


def process_txt_record(domain_name, record_name, record_value) -> None:
    """
    Process the TXT record.
    If FQDN found in prod hosted zone,
        If NS record exists
            If TXT record exists, Do nothing and return
            If TXT record not exists Add the TXT record and return
        If NS record not exists, raise AWSServiceRoute53RecordNotFoundException
    If FQDN not found in prod hosted zone,
        If FQDN found in dev hosted zone,
            Do NS record check and TXT check as above
        If FQDN not found in dev hosted zone,
            Go to next level domain and repeat the process
            If FQDN not found in any level, raise AWSServiceRoute53RecordNotFoundException

    Args:
        domain_name (str): The domain name.
        record_name (str): The record name.
        record_value (str): The record value.

    Raises:
        AWSServiceRoute53InvalidInputException: If the required variables are empty.
    """
    if not domain_name or not record_name or not record_value:
        raise exceptions.AWSServiceRoute53InvalidInputException(
            "Required variables domain_name, record_name or record_value are empty"
        )
    while True:
        for env in ["prod", "dev"]:
            logger.info("Processing domain %s in env %s", domain_name, env)
            if update_txt_record_by_env(domain_name, record_name, record_value, env):
                return
        domain_parts = domain_name.split(".")
        if len(domain_parts) <= 3:
            break
        domain_name = ".".join(domain_parts[-(len(domain_parts) - 1) :])
    raise exceptions.AWSServiceRoute53RecordNotFoundException(
        f"NS record for {domain_name} not found in any of the hosted zone"
    )


def update_txt_record_by_env(domain_name, record_name, record_value, env) -> bool:
    """
    Update the TXT record by environment.

    Args:
        domain_name (str): The domain name.
        record_name (str): The record name.
        record_value (str): The record value.
        env (str): The environment.

    Returns:
        bool: True if the record is successfully updated, otherwise False.
    """
    hosted_zone_id = get_hosted_zone_id_by_domain(domain_name, env)
    if hosted_zone_id and hosted_zone_id.startswith("/hostedzone/"):
        hosted_zone_id = hosted_zone_id.split("/")[2]
        logger.info(
            "Found Hosted zone ID : %s for the domain : %s, in env : %s",
            hosted_zone_id,
            domain_name,
            env,
        )
        if check_record_exist(hosted_zone_id, domain_name, "NS", env):
            logger.info(
                "NS record %s exists in the hosted zone",
                domain_name,
            )
            if not check_record_exist(hosted_zone_id, record_name, "TXT", env):
                logger.info(
                    "TXT record %s not exists in the hosted zone %s, updating the record",
                    record_name,
                    hosted_zone_id,
                )
                return change_resource_record_sets(
                    env,
                    hosted_zone_id,
                    record_name,
                    record_value,
                )
            else:
                logger.info(
                    "TXT record %s already exists in the hosted zone",
                    record_name,
                )
                return True
        else:
            logger.info(
                "NS record for %s not found in the hosted zone %s",
                domain_name,
                hosted_zone_id,
            )
            raise exceptions.AWSServiceRoute53RecordNotFoundException(
                f"NS record for {domain_name} not found in the hosted zone"
            )
    return False
