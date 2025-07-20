resource "cloudflare_record" "origin_dns_records" {
  for_each = { for record in local.origin_dns_records : record.name => record }
  zone_id  = data.cloudflare_zone.zone.id
  name     = each.value.name
  type     = each.value.type
  content  = each.value.content
  proxied  = each.value.proxied
  ttl      = each.value.ttl
  tags     = [for tag in toset(lookup(each.value, "tags", [])) : replace(lower(tag), "/[^a-z0-9_-]/", "")]
}
    
resource "cloudflare_tiered_cache" "tiered_cache" {
  count      = local.tiered_cache_settings != null ? 1 : 0
  zone_id    = data.cloudflare_zone.zone.id
  cache_type = local.tiered_cache_settings
}

resource "cloudflare_regional_tiered_cache" "regional_tiered_cache" {
  count   = local.regional_tiered_cache_settings != null ? 1 : 0
  zone_id = data.cloudflare_zone.zone.id
  value   = local.regional_tiered_cache_settings
}

resource "cloudflare_ruleset" "http_cache_settings" {
  count   = length(local.cache_settings) > 0 ? 1 : 0
  name    = "Cache Settings"
  phase   = "http_request_cache_settings"
  kind    = "zone"
  zone_id = data.cloudflare_zone.zone.id
  dynamic "rules" {
    for_each = [
      for cache_settings in local.cache_settings : cache_settings
    ]
    content {
      action      = lookup(rules.value, "action", "set_cache_settings")
      enabled     = lookup(rules.value, "enabled", true)
      description = rules.value.description
      expression  = rules.value.expression
      ref         = lookup(rules.value, "name", null)
      action_parameters {
        cache                      = lookup(rules.value, "cache", null)
        respect_strong_etags       = lookup(rules.value, "respect_strong_etags", null)
        origin_error_page_passthru = lookup(rules.value, "origin_error_page_passthru", null)
        origin_cache_control       = lookup(rules.value, "origin_cache_control", null)
        additional_cacheable_ports = lookup(rules.value, "additional_cacheable_ports", null)
        read_timeout               = lookup(rules.value, "read_timeout", null)
        dynamic "edge_ttl" {
          for_each = lookup(rules.value, "edge_ttl_mode", null) != null ? [1] : []
          content {
            mode    = rules.value.edge_ttl_mode
            default = lookup(rules.value, "edge_ttl_default", null)
            dynamic "status_code_ttl" {
              for_each = lookup(rules.value, "edge_ttl_status_code_settings", null) != null ? rules.value.edge_ttl_status_code_settings : []
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
          for_each = lookup(rules.value, "browser_ttl_mode", null) != null ? [1] : []
          content {
            mode    = rules.value.browser_ttl_mode
            default = lookup(rules.value, "browser_ttl_default", null)
          }
        }
        dynamic "serve_stale" {
          for_each = lookup(rules.value, "disable_stale_while_updating", null) != null ? [1] : []
          content {
            disable_stale_while_updating = rules.value.disable_stale_while_updating
          }

        }
        dynamic "cache_key" {
          for_each = lookup(rules.value, "cache_key_settings", null) != null ? rules.value.cache_key_settings : []
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
}

resource "cloudflare_ruleset" "http_request_redirect" {
  count   = length(local.redirect_settings) > 0 ? 1 : 0
  zone_id = data.cloudflare_zone.zone.id
  name    = "Request Redirect Rules"
  kind    = "zone"
  phase   = "http_request_dynamic_redirect"

  dynamic "rules" {
    for_each = [
      for redirect_setting in local.redirect_settings : redirect_setting
    ]
    content {
      action      = lookup(rules.value, "action", "redirect")
      expression  = rules.value.expression
      enabled     = lookup(rules.value, "enabled", true)
      description = rules.value.description
      action_parameters {
        from_value {
          status_code = rules.value.status_code
          target_url {
            value = lookup(rules.value, "target_url", null)
            expression = lookup(rules.value, "target_url_expression", null)
          }
          preserve_query_string = lookup(rules.value, "preserve_query_string", null)
        }
      }
    }
  }
}

resource "cloudflare_ruleset" "http_request_late_transform" {
  count   = length(local.header_late_transform_settings) > 0 ? 1 : 0
  zone_id = data.cloudflare_zone.zone.id
  name    = "Transform Rules for HTTP headers"
  kind    = "zone"
  phase   = "http_request_late_transform"

  dynamic "rules" {
    for_each = [
      for late_transform in local.header_late_transform_settings : late_transform
    ]
    content {
      action      = lookup(rules.value, "action", "rewrite")
      enabled     = lookup(rules.value, "enabled", true)
      description = rules.value.description
      expression  = rules.value.expression
      ref         = lookup(rules.value, "name", null)
      action_parameters {
        dynamic "headers" {
          for_each = { for header in rules.value.headers : header.name => header }
          content {
            name       = headers.key
            operation  = headers.value.operation
            expression = lookup(headers.value, "expression", null)
            value      = lookup(headers.value, "value", null)
          }
        }
      }
    }
  }
}

resource "cloudflare_managed_headers" "headers" {
  count   = length(local.managed_request_headers) > 0 || length(local.managed_response_headers) > 0 ? 1 : 0
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

resource "cloudflare_ruleset" "http_request_sanitize" {
  zone_id     = data.cloudflare_zone.zone.id
  name        = "Entrypoint for url normalization ruleset"
  kind        = "zone"
  phase       = "http_request_sanitize"
  description = "ruleset for controlling url normalization"

  rules {
    action     = lookup(local.http_request_sanitize, "action", "execute")
    enabled    = lookup(local.http_request_sanitize, "enabled", true)
    expression = local.http_request_sanitize.expression
    ref        = lookup(local.http_request_sanitize, "name", null)

    action_parameters {
      id = local.http_request_sanitize.action_parameters.id
      overrides {
        dynamic "rules" {
          for_each = local.http_request_sanitize.action_parameters.overrides.rules
          content {
            enabled = rules.value.enabled
            id      = rules.value.id
          }
        }
      }
    }
  }

}

resource "cloudflare_custom_pages" "custom_pages" {
  for_each = { for custom_page in local.custom_pages : custom_page.type => custom_page }
  zone_id  = data.cloudflare_zone.zone.id
  type     = each.key
  url      = each.value.url
  state    = each.value.state
}

resource "cloudflare_ruleset" "http_request_origin" {
  count   = length(local.origin_settings) > 0 ? 1 : 0
  zone_id = data.cloudflare_zone.zone.id
  name    = "Origin Rules"
  kind    = "zone"
  phase   = "http_request_origin"

  dynamic "rules" {
    for_each = [for origin_rule in local.origin_settings : origin_rule]
    content {
      action      = lookup(rules.value, "action", "route")
      enabled     = lookup(rules.value, "enabled", true)
      description = rules.value.description
      expression  = rules.value.expression
      ref         = lookup(rules.value, "name", null)
      action_parameters {
        host_header = lookup(rules.value, "host_header", null)
        dynamic "origin" {
          for_each = lookup(rules.value, "origin", null) != null ? [1] : []
          content {
            host = lookup(rules.value.origin, "host", null)
            port = lookup(rules.value.origin, "port", null)
          }
        }
        dynamic "sni" {
          for_each = lookup(rules.value, "sni", null) != null ? [1] : []
          content {
            value = lookup(rules.value.sni, "value", null)
          }
        }
      }
    }
  }
}

resource "cloudflare_ruleset" "configuration_setting" {
  count   = length(local.configuration_settings) > 0 ? 1 : 0
  kind    = "zone"
  name    = "Configuration Settings"
  phase   = "http_config_settings"
  zone_id = data.cloudflare_zone.zone.id
  dynamic "rules" {
    for_each = [for configuration_rule in local.configuration_settings : configuration_rule]
    content {
      action      = lookup(rules.value, "action", "set_config")
      enabled     = lookup(rules.value, "enabled", true)
      description = rules.value.description
      expression  = rules.value.expression
      ref         = lookup(rules.value, "name", null)
      action_parameters {
        automatic_https_rewrites = lookup(rules.value, "automatic_https_rewrites", null)
        bic                      = lookup(rules.value, "bic", null)
        disable_apps             = lookup(rules.value, "disable_apps", null)
        disable_zaraz            = lookup(rules.value, "disable_zaraz", null)
        disable_rum              = lookup(rules.value, "disable_rum", null)
        email_obfuscation        = lookup(rules.value, "email_obfuscation", null)
        fonts                    = lookup(rules.value, "fonts", null)
        hotlink_protection       = lookup(rules.value, "hotlink_protection", null)
        mirage                   = lookup(rules.value, "mirage", null)
        opportunistic_encryption = lookup(rules.value, "opportunistic_encryption", null)
        polish                   = lookup(rules.value, "polish", null)
        rocket_loader            = lookup(rules.value, "rocket_loader", null)
        security_level           = lookup(rules.value, "security_level", null)
        ssl                      = lookup(rules.value, "ssl", null)
        sxg                      = lookup(rules.value, "sxg", null)
      }
    }
  }
}

resource "cloudflare_ruleset" "http_request_rewrite" {
  count   = length(local.url_rewrite_settings) > 0 ? 1 : 0
  kind    = "zone"
  name    = "URL Rewrite Rules"
  phase   = "http_request_transform"
  zone_id = data.cloudflare_zone.zone.id
  dynamic "rules" {
    for_each = [for url_rewrite_rule in local.url_rewrite_settings : url_rewrite_rule]
    content {
      action      = lookup(rules.value, "action", "rewrite")
      enabled     = lookup(rules.value, "enabled", true)
      description = rules.value.description
      expression  = rules.value.expression
      ref         = lookup(rules.value, "name", null)
      action_parameters {
        uri {
          dynamic "path" {
            for_each = lookup(rules.value, "uri_path", null) != null ? [1] : []
            content {
              value      = lookup(rules.value.uri_path, "value", null)
              expression = lookup(rules.value.uri_path, "expression", null)
            }
          }
          dynamic "query" {
            for_each = lookup(rules.value, "uri_query", null) != null ? [1] : []
            content {
              value      = lookup(rules.value.uri_query, "value", null)
              expression = lookup(rules.value.uri_query, "expression", null)
            }
          }
        }
      }
    }
  }
}

resource "cloudflare_ruleset" "response_header_transform" {
  count   = length(local.response_header_transform_settings) > 0 ? 1 : 0
  kind    = "zone"
  name    = "Response Header Transformation"
  phase   = "http_response_headers_transform"
  zone_id = data.cloudflare_zone.zone.id

  dynamic "rules" {
    for_each = [for response_transform in local.response_header_transform_settings : response_transform]
    content {
      action      = lookup(rules.value, "action", "rewrite")
      enabled     = lookup(rules.value, "enabled", true)
      description = rules.value.description
      expression  = rules.value.expression
      ref         = lookup(rules.value, "name", null)
      action_parameters {
        dynamic "headers" {
          for_each = { for header in rules.value.headers : header.name => header }
          content {
            name       = headers.key
            operation  = headers.value.operation
            expression = lookup(headers.value, "expression", null)
            value      = lookup(headers.value, "value", null)
          }
        }
      }
    }
  }
}

resource "cloudflare_ruleset" "compression_rules" {
  count   = length(local.compression_settings) > 0 ? 1 : 0
  kind    = "zone"
  name    = "default"
  phase   = "http_response_compression"
  zone_id = data.cloudflare_zone.zone.id
  dynamic "rules" {
    for_each = [for compression_rule in local.compression_settings : compression_rule]
    content {
      action      = lookup(rules.value, "action", "compress_response")
      enabled     = lookup(rules.value, "enabled", true)
      description = rules.value.description
      expression  = rules.value.expression
      ref         = lookup(rules.value, "name", null)
      action_parameters {
        dynamic "algorithms" {
          for_each = [for algorithm in rules.value.algorithms : algorithm]
          content {
            name = algorithms.value
          }
        }
      }
    }
  }
}
