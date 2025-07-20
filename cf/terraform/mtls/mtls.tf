# # Set Cloudflare Access Application Settings
# # https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/access_application

resource "cloudflare_zero_trust_access_application" "cba_mtls_application" {
  domain           = lookup(local.mtls_params, "domain", local.zone_name)
  name             = local.zone_name
  session_duration = lookup(local.mtls_params, "session_duration", "24h")
  type             = "self_hosted"
  account_id       = var.account_id
}

# Set Access Policies
resource "cloudflare_zero_trust_access_policy" "cba_mtls_policy" {
  for_each       = { for index, cert in local.mtls_params.leaf_common_names : index => cert }
  application_id = cloudflare_zero_trust_access_application.cba_mtls_application.id
  account_id     = var.account_id
  name           = "${local.zone_name} mTLS Policy ${each.key + 1}"
  precedence     = each.key + 1   # The order in which the policy is applied
  decision       = "non_identity" # equivalent to Service Auth
  include {
    certificate = "true"
  }
  require {
    common_name = each.value.common_name
  }
}

resource "terraform_data" "mtls" {
  for_each = {
    for cert in local.mtls_params.certs : cert.name => cert
  }
  input = {
    name            = each.key
    zero_trust_name = lookup(local.mtls_data, each.key, { "zero_trust_name" : "" }).zero_trust_name
    cert_id         = lookup(local.mtls_data, each.key, { "cert_id" : "" }).cert_id
    domain          = lookup(local.mtls_data, each.key, {"domain": ""}).domain
  }
}

resource "cloudflare_authenticated_origin_pulls" "zone_aop" {
  zone_id = data.cloudflare_zone.zone.id
  enabled = try(local.mtls_params.authenticated_origin_pulls_settings, false)
}
