import os

local                           = os.environ.get("LOCAL")
gh_signing_key                  = os.environ.get("GITHUB_APP_PRIVATE_KEY")
gh_app_id                       = os.environ.get("GITHUB_APP_CLIENT_ID")
gh_app_installation_id          = os.environ.get("GITHUB_APP_INSTALLATION_ID")
state_bucket_name               = os.environ.get("TF_STATE_BUCKET_NAME")
state_lock_dynamodb_table       = os.environ.get("TF_STATE_LOCK_DYNAMODB_TABLE")
cf_initial_api_token            = os.environ.get("CLOUDFLARE_INITIAL_API_TOKEN")
cf_token_ttl_minutes            = int(os.getenv("CLOUDFLARE_TOKEN_TTL_MINUTES", "5"))
dev_txt_aws_access_key_id       = os.environ.get("DEV_TXT_AWS_ACCESS_KEY_ID")
dev_txt_aws_secret_access_key   = os.environ.get("DEV_TXT_AWS_SECRET_ACCESS_KEY")
prod_txt_aws_access_key_id      = os.environ.get("PROD_TXT_AWS_ACCESS_KEY_ID")
prod_txt_aws_secret_access_key  = os.environ.get("PROD_TXT_AWS_SECRET_ACCESS_KEY")
github_jkws_cache_expiry        = int(os.getenv("JWKS_CACHE_EXPIRY", "3600"))
idp_private_key                 = os.getenv("GROUP_IDP_PRIVATE_KEY", "") # Staging private key - To be updated
GITHUB_JKWS_CACHE_RETRY_COUNT   = 1
ACCOUNTS_FILE_PATH              = "cf/accounts.yml"
WORKING_DIR_PREFIX              = "workingdir_"
FQDN_NAME_PATTERN               = "^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,}$"
OIDC_ISSUER                     = "https://token.actions.githubusercontent.com"
OIDC_AUDIENCE                   = "api://DHPRunnerAPI"
OIDC_JWT_LEEWAY                 = 10
AUTH_HEADER                     = "X-Github-Auth-Header"
AUTH_TOKEN_PREFIX               = "Bearer "
GITHUB_JWKS_URL                 = "https://token.actions.githubusercontent.com/.well-known/jwks"
TENANT_REPO_PREFIX              = "CBA-General/groupsec-edgesecurity-tenant-"
TENANT_ONBOARDING_YAML          = "tenant_onboarding_settings.yml"
SELFSERVICE_REPO_NAME           = "CBA-General/groupsec-edgesecurity-selfservice"
VENAFI_CLIENT_ID                = "edge-security.int.stg.venafi-staging" # Staging Venafi client ID - To be updated
CERT_PARAMETERS_FILE_NAME       = "cert_parameters.yml"

# CERT Constants
CSR_REQUIRED_KEYS               = ["name", "common_name"]
# Optional keys for CSR - If not provided, first value will be used as default
CSR_OPTIONAL_KEYS               = {
    "country": ["AU"],
    "state": ["NSW"],
    "locality": ["Sydney"],
    "organization": ["Commonwealth Bank of Australia"],
    "organizational_unit": ["Group Security"],
    "key_type": ["rsa2048"],
    "signer": ["ext", "ext-ev"],
    "scope": ["account","zone"],
}



# InputModel Validation
VALID_ACTIONS       = ["plan", "apply"]
VALID_CONFIG_TYPES  = ["account", "zone", "cdn", "security", "tls", "cert"]


# State file suffix map
STATE_FILE_SUFFIX_MAP = {
    "account": "account.terraform.tfstate",
    "zone": "zone.terraform.tfstate",
    "cdn": "cdn/terraform.tfstate",
    "security": "security/terraform.tfstate",
    "tls": "tls/terraform.tfstate",
}

# Terraform backend.tf template
BACKEND_TEMPLATE = """terraform {{
  backend "s3" {{
    bucket = "{bucket}"
    key    = "{key}"
    dynamodb_table = "{dynamodb_table}"
    region = "ap-southeast-2"
  }}
}}
"""

# Error messages
NOT_AUTHORIZED_ERROR = "Not Authorized"
