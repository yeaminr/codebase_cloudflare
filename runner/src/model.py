"""
This module contains the model classes.
"""

from typing import Optional
from enum import Enum
from pydantic import BaseModel, field_validator

from runner.src import api_constant
from cf.python.src import helpers


class EnvironmentModel(str, Enum):
    """
    Enum for the environment model.
    """

    dev = "dev"
    tst = "tst"
    stg = "stg"
    prd = "prd"


class InputModel(BaseModel):
    """
    Input model.
    """

    environment: EnvironmentModel
    action: str
    config_type: str
    fqdn: Optional[str] = None

    @property
    def account_id(self) -> str:
        """
        Get the account ID.
        """
        return helpers.get_account_id(
            self.environment.value, api_constant.ACCOUNTS_FILE_PATH
        )

    @property
    def input_vars_path(self) -> str:
        """
        Get the input vars path.
        """
        return helpers.get_input_vars_path(
            self.environment.value, self.fqdn, self.config_type
        )

    @field_validator("environment")
    @classmethod
    def environment(cls, value):
        """
        Validate the environment.
        """
        if value is None or value not in EnvironmentModel:
            raise ValueError("Environment is not valid.")
        return value

    @field_validator("action")
    @classmethod
    def action(cls, value):
        """
        Validate the action.
        """
        if value is None or value == "" or value not in api_constant.VALID_ACTIONS:
            raise ValueError(
                "Action is not valid. It should be either 'plan' or 'apply'."
            )
        return value

    @field_validator("config_type")
    @classmethod
    def config_type(cls, value):
        """
        Validate the config type.
        """
        if value is None or value == "" or value not in api_constant.VALID_CONFIG_TYPES:
            raise ValueError(
                f"Config type is not valid. It should be one of {api_constant.VALID_CONFIG_TYPES}"
            )
        return value


class CertOutputModel(BaseModel):
    """
    Cert output model
    """
    csr: Optional[str] = None
    csr_id: Optional[str] = None
    csr_status: Optional[str] = "to_be_created"
    # cert: Optional[str] = None
    cert_status: Optional[str] = "to_be_uploaded"
    expiresin: Optional[str] = None
    common_name: Optional[str] = None
    sans: Optional[list] = None
    error: Optional[str] = None
    venafi_status: Optional[str] = "to_be_created"

    
