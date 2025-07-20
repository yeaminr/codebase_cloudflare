"""
Constants for the Runner API
"""
import os

local                               = os.environ.get("LOCAL")
gh_signing_key                      = os.environ.get("GITHUB_APP_PRIVATE_KEY")
gh_app_id                           = os.environ.get("GITHUB_APP_CLIENT_ID")
gh_app_installation_id              = os.environ.get("GITHUB_APP_INSTALLATION_ID")
gh_rstd_org_installation_id         = os.environ.get("GITHUB_RESTRICTED_ORG_INSTALLATION_ID")
state_bucket_name                   = os.environ.get("TF_STATE_BUCKET_NAME")
state_lock_dynamodb_table           = os.environ.get("TF_STATE_LOCK_DYNAMODB_TABLE")
cf_initial_api_token                = os.environ.get("CLOUDFLARE_INITIAL_API_TOKEN")
cf_initial_api_token_id             = os.environ.get("CLOUDFLARE_INITIAL_API_TOKEN_ID")
cf_perm_grp_api_tokens_write        = "686d18d5ac6c441c867cbf6771e58a0a" # "API Tokens Write"
cf_initial_token_validity           = 86400 # 60 days in minutes
cf_token_verify_url                 = "https://api.cloudflare.com/client/v4/user/tokens/verify"
cf_token_ttl_minutes                = int(os.getenv("CLOUDFLARE_TOKEN_TTL_MINUTES", "5"))
nonprod_txt_aws_access_key_id       = os.environ.get("DEV_TXT_AWS_ACCESS_KEY_ID")
nonprod_txt_aws_secret_access_key   = os.environ.get("DEV_TXT_AWS_SECRET_ACCESS_KEY")
prod_txt_aws_access_key_id          = os.environ.get("PROD_TXT_AWS_ACCESS_KEY_ID")
prod_txt_aws_secret_access_key      = os.environ.get("PROD_TXT_AWS_SECRET_ACCESS_KEY")
github_jkws_cache_expiry            = int(os.getenv("JWKS_CACHE_EXPIRY", "3600"))
idp_private_key                     = os.getenv("GROUP_IDP_PRIVATE_KEY", "")
cba_aws_dns_record_env              = os.getenv("CBA_AWS_DNS_RECORD_ENV", "nonprod") # Valid values are "nonprod" & "prod" loaded from vault
venafi_client_id                    = os.getenv("VENAFI_API_CLIENT_NAME")
GITHUB_JKWS_CACHE_RETRY_COUNT       = 1
ACCOUNTS_FILE_PATH                  = "cf/accounts.yml"
DOMAIN_GROUPS_FILE_PATH             = "cf/domain_groups.yml"
WORKING_DIR_PREFIX                  = "workingdir_"
FQDN_NAME_PATTERN                   = "^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,}$"
CHANGE_NUMBER_PATTERN               = "^CHG[0-9]{1,10}$"
CLOUDFLARE_RESOURCE_TYPE_PATTERN    = "^cloudflare_[a-z_]+"
OIDC_ISSUER                         = "https://token.actions.githubusercontent.com"
OIDC_AUDIENCE                       = "api://DHPRunnerAPI"
OIDC_JWT_LEEWAY                     = 10
AUTH_HEADER                         = "X-Github-Auth-Header"
AUTH_TOKEN_PREFIX                   = "Bearer "
GITHUB_JWKS_URL                     = "https://token.actions.githubusercontent.com/.well-known/jwks"
TENANT_REPO_PREFIX                  = "CBA-Edge-Security-Platform-RSTD/groupsec-edgesecurity-tenant-"
TENANT_ONBOARDING_YAML              = "tenant_onboarding_settings.yml"
SELFSERVICE_REPO_NAME               = "CBA-General/groupsec-edgesecurity-selfservice"
GITHUB_RSTD_ORG_URL_PREFIX          = "https://api.github.com/repos/CBA-Edge-Security-Platform-RSTD/"
CERT_PARAMETERS_FILE_NAME           = "cert_parameters.yml"
TENANT_ALLOWED_CONFIGS              = ["cdn", "security", "tls", "cert", "mtls", "workers", "app_list"]
TEST_REPORT_DIRECTORY               = "pytest_results"
MTLS_TENANT_REPO_FOLDER             = "bundles"
TO_BE_GENERATED                     = "To be generated"
TO_BE_REMOVED                       = "To be removed"
BANKWEST_DOMAINS                    = ["bankwest.com.au"]
BANKWEST_DNS_RECORD_REPO            = "CBA-General/bwa-dnse-r53-prd"
BANKWEST_DNS_RECORD_REPO_PATH       = "octodns/zones"
BANKWEST_DNS_RECORD_REPO_BRANCH     = "main"
GITHUB_COMMITTER_NAME               = "edgesecurityautomationapp[bot]"
GITHUB_COMMITTER_EMAIL              = "edgesecurityautomationapp[bot]@users.noreply.github.com"
REPO_CONFIG_APPLY_BRANCH            = "main"
AUTHORIZED_ACCOUNT_REPOS            = [
  "CBA-Edge-Security-Platform-RSTD/groupsec-edgesecurity-cloudflare-account-config",
]
AUTHORIZED_TOKEN_REPOS            = [
  "CBA-Edge-Security-Platform-RSTD/groupsec-edgesecurity-tenant-test-automation",
]
CLOUDFLARE_SKIP_NOTIFICATIONS = ["DDoS Protection: Advanced HTTP DDoS Attack Alert", "Cloudflare SOC L7", "Failing LogPush, Job Disabled"]

AWS_ENV_MAPPING = {
        "prd": "prod",
        "dev": "nonprod",
        "tst": "nonprod",
        "stg": "nonprod",
    }
# Bankwest TXT Record Constants
BANKWEST_TXT_RECORD_YML_CONTENT = """
{txt_record_name}:
  type: {txt_record_type}
  value: {txt_record_value}
  ttl: {txt_record_ttl}
"""
BANKWEST_COMMIT_MESSAGE        = "[CYB] - Cloudflare - DCV TXT record - {fqdn} - {change_number}"
BANKWEST_PULL_REQUEST_TEMPLATE = """
## Description
Adding TXT record {txt_record_value} for {fqdn} for Cloudflare verification.
Change Number: {change_number}

## Changes
Adding TXT record for {fqdn} for Cloudflare verification.
Change Number: {change_number}

## Checklist
- [x] SNOW change record in relation to this Pull-Request ({change_number})
- [ ] Code has been reviewed by a team member
- [x] Commits have been squashed to a reasonable number (up to 5)

## Additional information
**Links:**

**Screenshots:**
"""

# Vault Constants
VAULT_URL                      = "https://secrets.vault.cba"
VAULT_LDAP_AUTH_PATH           = "v1/auth/ldap-bots/login"
VAULT_LDAP_AUTH_USERNAME       = os.environ.get("VAULT_LDAP_AUTH_USERNAME")
VAULT_LDAP_AUTH_PASSWORD       = os.environ.get("VAULT_LDAP_AUTH_PASSWORD")
VAULT_NAMESPACE_CYBER_DHP      = "chp/DHP-Aws-CyberSecurityPlatform1"
VAULT_NAMESPACE_CYBER_DEV      = "cybersecurity/edgesecurity-vault-dev"
vault_secret_path_map_dhp = {
    "dev": "dev/apps/secrets/d-s-es1-tf-ecsservice",
    "tst": "test2/apps/secrets/t2-s-es1-tf-ecsservice",
    "stg": "stg/apps/secrets/s-s-es1-tf-ecsservice",
    "prd": "prod/apps/secrets/p-s-es1-tf-ecsservice"
}

# CERT Constants
CERT_REQUIRED_KEYS = ["name", "common_name", "sans", "tso"]
# Optional keys for Cert - If not provided, first value will be used as default
CERT_OPTIONAL_KEYS = {
    "country": "AU",
    "state": "NSW",
    "locality": "Sydney",
    "organization": "Commonwealth Bank of Australia",
    "organizational_unit": "Group Security",
    "key_type": "rsa2048",
    "signer": "", # set in code
    "scope": "account"
}
CERT_CSR_ORG_VALUES = {
    # list from: https://commbank.atlassian.net/wiki/spaces/CEM/pages/199327817/Certificate+Management+FAQs#What-is-the-Organization-value-to-be-used-for-External-Certificates?
    "ext": ["Commonwealth Bank of Australia", "Colonial First State Investments Limited", "Commonwealth Securities Limited", "Bankwest"],
    "ext-ev": ["Commonwealth Bank of Australia", "Commonwealth Bank Of Australia (Bankwest)"]
}

MTLS_LEAF_COMMON_NAMES_REQUIRED_KEYS = ["friendlyname", "common_name"]
MTLS_CERTS_REQUIRED_KEYS = ["name", "ca_chain_filename"]

# InputModel Validation
VALID_ACTIONS       = ["plan", "apply", "validate"]
VALID_CONFIG_TYPES  = [
 "account", "zone", "cdn", "security", "tls", "cert", "mtls", "workers", "app_list"
]


# State file suffix map
STATE_FILE_SUFFIX_MAP = {
    "account": "account.terraform.tfstate",
    "zone": "zone.terraform.tfstate",
    "cdn": "cdn/terraform.tfstate",
    "security": "security/terraform.tfstate",
    "tls": "tls/terraform.tfstate",
    "cert": "cert/terraform.tfstate",
    "mtls": "mtls/terraform.tfstate",
    "workers": "workers/terraform.tfstate",
    "app_list": "app_list/terraform.tfstate",
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

TERRAFORM_PROVIDER_TEMPLATE = """
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.5"
    }
  }
}

provider \"cloudflare\" {}
"""

# Error messages
NOT_AUTHORIZED_ERROR              = "Not Authorized"
HTTP_AUTHORIZATION_ERROR_RESPONSE = "The requesting repo {repo_name} or branch {branch} is not authorized to perform {action} on {config_type} config"
CF_TERRAFORMING_RESOURCES         = ["cloudflare_ruleset", "cloudflare_record"]
TERRAFORM_BINARY_PATH             = "/usr/local/bin/terraform"
