locals {
  zone_inputs                   = yamldecode(file("${path.module}/zone_parameters.yml"))
  zone_name                     = local.zone_inputs.fqdn
  security_params               = yamldecode(file("${path.module}/security_parameters.yml"))
  waf_managed_ruleset           = local.security_params.waf_managed_ruleset
  waf_custom_ruleset            = local.security_params.waf_custom_ruleset
  waf_rate_limiting_ruleset     = local.security_params.waf_rate_limiting_ruleset
  bot_management_settings       = local.security_params.bot_management_settings
  logpush_job_settings          = lookup(local.security_params, "logpush_job_settings_splunk", [])
  logpush_pipeline_job_settings = lookup(local.security_params, "logpush_pipeline_job_settings", [])
  content_scanning              = lookup(local.security_params, "content_scanning", true)
  log_custom_fields = {
    for k, v in local.security_params : k => v
    if k == "log_custom_fields" && v != null
  }
}
