locals {
  cdn_inputs               = yamldecode(file(var.cdn_config_file))
  zone_inputs              = yamldecode(file(var.zone_config_file))
  zone_name                = local.zone_inputs.fqdn
  dns_records              = lookup(local.cdn_inputs, "dns_records", [])
  cache_settings           = lookup(local.cdn_inputs, "cache_settings", [])
  redirect_settings        = lookup(local.cdn_inputs, "redirect_settings", [])
  enable_true_client_ip    = lookup(local.cdn_inputs, "enable_true_client_ip", false)
  managed_request_headers  = lookup(local.cdn_inputs, "managed_request_headers", [])
  managed_response_headers = lookup(local.cdn_inputs, "managed_response_headers", [])
}

resource "cloudflare_record" "record" {
  for_each = { for record in local.dns_records : record.name => record }
  zone_id  = data.cloudflare_zone.zone.id
  name     = each.key
  content  = each.value.content
  type     = each.value.type
  ttl      = each.value.ttl
  tags     = each.value.tags
}

resource "cloudflare_ruleset" "http_cache_settings" {
  for_each = {
    for cache_settings in local.cache_settings : cache_settings.name => cache_settings
    if length(local.cache_settings) > 0
  }
  name    = each.key
  phase   = "http_request_cache_settings"
  kind    = "zone"
  zone_id = data.cloudflare_zone.zone.id
  rules {
    action     = "set_cache_settings"
    expression = each.value.expression
    enabled    = lookup(each.value, "enabled", true)
    action_parameters {
      cache                      = lookup(each.value, "cache", null)
      respect_strong_etags       = lookup(each.value, "respect_strong_etags", null)
      origin_error_page_passthru = lookup(each.value, "origin_error_page_passthru", null)
      origin_cache_control       = lookup(each.value, "origin_cache_control", null)
      additional_cacheable_ports = lookup(each.value, "additional_cacheable_ports", null)
      read_timeout               = lookup(each.value, "read_timeout", null)
      dynamic "edge_ttl" {
        for_each = lookup(each.value, "edge_ttl_mode", null) != null ? [1] : []
        content {
          mode    = each.value.edge_ttl_mode
          default = lookup(each.value, "edge_ttl_default", null)
          dynamic "status_code_ttl" {
            for_each = lookup(each.value, "edge_ttl_status_code_settings", null) != null ? each.value.edge_ttl_status_code_settings : []
            content {
              status_code = lookup(status_code_ttl.value, "code", null)
              value       = lookup(status_code_ttl.value, "value", null)
              dynamic "status_code_range" {
                for_each = lookup(status_code_ttl.value, "from", null) != null || lookup(status_code_ttl.value, "to", null) != null ? [1] : []
                content {
                  from = lookup(status_code_ttl.value, "from", null)
                  to   = lookup(status_code_ttl.value, "to", null)
                }
              }
            }
          }
        }
      }
      dynamic "browser_ttl" {
        for_each = lookup(each.value, "browser_ttl_mode", null) != null ? [1] : []
        content {
          mode    = each.value.browser_ttl_mode
          default = lookup(each.value, "browser_ttl_default", null)
        }
      }
      dynamic "serve_stale" {
        for_each = lookup(each.value, "disable_stale_while_updating", null) != null ? [1] : []
        content {
          disable_stale_while_updating = each.value.disable_stale_while_updating
        }

      }
      dynamic "cache_key" {
        for_each = lookup(each.value, "cache_key_settings", null) != null ? each.value.cache_key_settings : []
        content {
          ignore_query_strings_order = lookup(cache_key.value, "ignore_query_strings_order", null)
          cache_deception_armor      = lookup(cache_key.value, "cache_deception_armor", null)
          cache_by_device_type       = lookup(cache_key.value, "cache_by_device_type", null)
          dynamic "custom_key" {
            for_each = lookup(cache_key.value, "custom_key_enabled", null) != null ? [1] : []
            content {
              dynamic "cookie" {
                for_each = lookup(cache_key.value, "cookie_include", null) != null || lookup(cache_key.value, "cookie_presence", null) != null ? [1] : []
                content {
                  include        = lookup(cache_key.value, "cookie_include", null)
                  check_presence = lookup(cache_key.value, "cookie_presence", null)
                }
              }
              dynamic "header" {
                for_each = lookup(cache_key.value, "header_include", null) != null || lookup(cache_key.value, "header_presence", null) != null || lookup(cache_key.value, "header_exclude_origin", null) != null || lookup(cache_key.value, "header_contains", null) != null ? [1] : []
                content {
                  include        = lookup(cache_key.value, "header_include", null)
                  check_presence = lookup(cache_key.value, "header_presence", null)
                  exclude_origin = lookup(cache_key.value, "header_exclude_origin", null)
                  contains       = lookup(cache_key.value, "header_contains", null)
                }
              }
              dynamic "host" {
                for_each = lookup(cache_key.value, "host_resolved", null) != null ? [1] : []
                content {
                  resolved = lookup(cache_key.value, "host_resolved", null)
                }
              }
              dynamic "query_string" {
                for_each = lookup(cache_key.value, "query_string_include", null) != null || lookup(cache_key.value, "query_string_exclude", null) != null ? [1] : []
                content {
                  include = lookup(cache_key.value, "query_string_include", null)
                  exclude = lookup(cache_key.value, "query_string_exclude", null)
                }
              }
              dynamic "user" {
                for_each = lookup(cache_key.value, "user_key", null) != null ? [1] : []
                content {
                  device_type = cache_key.value.user_key == "device_type" ? true : null
                  geo         = cache_key.value.user_key == "geo" ? true : null
                  lang        = cache_key.value.user_key == "lang" ? true : null
                }
              }
            }
          }
        }
      }
    }
  }
}

resource "cloudflare_ruleset" "http_request_redirect" {
  for_each = {
    for redirect_setting in local.redirect_settings : redirect_setting.name => redirect_setting
    if length(local.redirect_settings) > 0
  }
  zone_id = data.cloudflare_zone.zone.id
  name    = each.key
  kind    = "zone"
  phase   = "http_request_dynamic_redirect"

  rules {
    action     = "redirect"
    expression = each.value.expression
    enabled    = lookup(each.value, "enabled", true)
    action_parameters {
      from_value {
        status_code = each.value.status_code
        target_url {
          value = each.value.target_url
        }
        preserve_query_string = each.value.preserve_query_string
      }
    }

  }
}

resource "cloudflare_managed_headers" "headers" {
  zone_id = data.cloudflare_zone.zone.id
  dynamic "managed_request_headers" {
    for_each = local.managed_request_headers
    content {
      id      = managed_request_headers.value
      enabled = true
    }
  }

  dynamic "managed_response_headers" {
    for_each = local.managed_response_headers
    content {
      id      = managed_response_headers.value
      enabled = true
    }
  }

}
