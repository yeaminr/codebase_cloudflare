# Read the input YAML file for security configuration and decode the content into local variables  
locals {
  security_params           = yamldecode(file("${path.module}/security_parameters.yml"))
  zone_inputs               = yamldecode(file("zone_parameters.yml"))
  zone_name                 = local.zone_inputs.fqdn
  waf_managed_ruleset       = local.security_params.waf_managed_ruleset
  waf_custom_ruleset        = local.security_params.waf_custom_ruleset
  waf_rate_limiting_ruleset = local.security_params.waf_rate_limiting_ruleset

}

variable "account_id" {
  type        = string
  description = "Cloudflare account ID"
  validation {
    condition     = can(regex("^[a-z0-9]{32}$", var.account_id))
    error_message = "The Cloudflare account ID must be valid that has only 32 characters from a-z and 0-9."
  }
}
