# Read the YAML input file
locals {
  zone_inputs                        = yamldecode(file("${path.module}/zone_parameters.yml"))
  zone_name                          = local.zone_inputs.fqdn
  cdn_inputs                         = yamldecode(file("${path.module}/cdn_parameters.yml"))
  origin_dns_records                 = local.cdn_inputs.origin_dns_records
  tiered_cache_settings              = lookup(local.cdn_inputs, "tiered_cache_settings", null)
  regional_tiered_cache_settings     = lookup(local.cdn_inputs, "regional_tiered_cache_settings", null)
  cache_settings                     = lookup(local.cdn_inputs, "cache_settings", [])
  header_late_transform_settings     = lookup(local.cdn_inputs, "request_header_late_transform_settings", [])
  redirect_settings                  = lookup(local.cdn_inputs, "redirect_settings", [])
  managed_request_headers            = lookup(local.cdn_inputs, "managed_request_headers", [])
  managed_response_headers           = lookup(local.cdn_inputs, "managed_response_headers", [])
  http_request_sanitize              = lookup(local.cdn_inputs, "http_request_sanitize", {})
  custom_pages                       = lookup(local.cdn_inputs, "custom_pages", [])
  origin_settings                    = lookup(local.cdn_inputs, "origin_settings", [])
  configuration_settings             = lookup(local.cdn_inputs, "configuration_settings", [])
  url_rewrite_settings               = lookup(local.cdn_inputs, "url_rewrite_settings", [])
  response_header_transform_settings = lookup(local.cdn_inputs, "response_header_transform_settings", [])
  compression_settings               = lookup(local.cdn_inputs, "compression_settings", [])

}
