# Read the YAML input file
locals {
  account_input                        = yamldecode(file("${path.module}/account_parameters.yml"))
  policy_name_rate_control_bypass_list = local.account_input.policy_name_rate_control_bypass_list
  rate_control_bypass_global_list      = local.account_input.rate_control_bypass_global_list
  group_wide_whitelist                 = local.account_input.group_wide_whitelist
  group_wide_blacklist                 = local.account_input.group_wide_blacklist
}

variable "account_id" {
  type        = string
  description = "Cloudflare account ID"
  validation {
    condition     = can(regex("^[a-z0-9]{32}$", var.account_id))
    error_message = "The Cloudflare account ID must be valid that has only 32 characters from a-z and 0-9."
  }
}
