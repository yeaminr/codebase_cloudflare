"""
Manage Cloudflare notifications
"""

import logging

from cloudflare import Cloudflare
from runner.src import api_constant, exceptions, helpers
from runner.src.model import InputModel
from runner.src import cloudflare_token_service

logger = logging.getLogger(__name__)


def add_zone_to_all_notifications_in_account(input_model: InputModel):
    """
    Add zone to all available notification in the account

    Args
    ----
    env (str): Environment name
    zone_name (str): Zone name to add to notifications
    """
    logger.info(
        "Adding zone %s to all notifications in account %s",
        input_model.fqdn,
        input_model.environment,
    )
    env = input_model.environment
    zone_name = input_model.fqdn

    try:
        # make scoped token
        token_store, scoped_api_token = (
            cloudflare_token_service.set_cloudflare_scoped_token(input_model)
        )
        # get zone ID
        zone_id = helpers.get_zone_id(zone_name, scoped_api_token)
        # get account ID
        account_id = helpers.get_account_id(env, api_constant.ACCOUNTS_FILE_PATH)
        # set up Cloudflare client
        cf_client = Cloudflare(api_token=scoped_api_token)
        # add zone to all notifications in the account
        for alert in cf_client.alerting.policies.list(account_id=account_id):
            logger.info(
                "Processing notification %s in account %s", alert.name, account_id
            )
            # some notifications are not applicable
            if alert.name in api_constant.CLOUDFLARE_SKIP_NOTIFICATIONS:
                logger.info("Skipping notification: %s", alert.name)
                continue

            filters = alert.filters
            if not filters:
                zone_filters = []
            elif not filters.zones:
                zone_filters = []
            else:
                zone_filters = filters.zones
            logger.info(
                "Current zone filters for notification %s: %s",
                alert.name,
                zone_filters,
            )

            # skip if zone already exists in the notification
            if zone_id in zone_filters:
                logger.info(
                    "Zone %s already exists in notification %ss", zone_name, alert.name
                )
                continue

            # add zone to the notification
            zone_filters.append(zone_id)
            filters.zones = zone_filters

            # serialize mechanisms
            mech = {"email": [], "webhooks": [], "pagerduty": []}
            for k, v in alert.mechanisms.items():
                for mechanism in v:
                    mech[k] = [{"id": mechanism.to_dict()["id"]}]
            
            logger.info("mechanisms: %s", mech)

            logger.info("New zone filters %s", filters.zones)
            res = cf_client.alerting.policies.update(
                policy_id=alert.id,
                account_id=account_id,
                alert_type=alert.alert_type,
                description=alert.description,
                enabled=alert.enabled,
                filters=filters.to_dict(),
                mechanisms=mech,
                name=alert.name,
            )
            logger.info(
                "Added zone %s to notification %s in account %s: %s",
                zone_name,
                alert.name,
                account_id,
                res,
            )
    except Exception as e:
        logger.error("Error adding zone to notifications: %s", e)
        raise exceptions.NotificationServiceException(
            "Error adding zone to notifications"
        ) from e
    finally:
        cf_initial_api_token = helpers.check_initial_token(input_model.environment)
        deleted_tokens = cloudflare_token_service.delete_all_tokens(
            cf_initial_api_token, token_store
        )
        remaining = list(set(token_store) - set(deleted_tokens))
        logger.info("Cloudflare active scoped tokens: %s", remaining)
