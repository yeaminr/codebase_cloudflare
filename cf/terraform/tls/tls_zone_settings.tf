resource "cloudflare_zone_settings_override" "settings_override" {
  # https://developers.cloudflare.com/api/operations/zone-settings-edit-zone-settings-info
  zone_id = data.cloudflare_zone.zone.id
  settings {
    always_online            = lookup(local.zone_settings, "always_online", "off")
    always_use_https         = lookup(local.zone_settings, "always_use_https", "off")
    automatic_https_rewrites = lookup(local.zone_settings, "automatic_https_rewrites", "off")
    brotli                   = lookup(local.zone_settings, "brotli", "on")
    browser_cache_ttl        = lookup(local.zone_settings, "browser_cache_ttl", 14400)
    browser_check            = lookup(local.zone_settings, "browser_check", "on")
    cache_level              = lookup(local.zone_settings, "cache_level", "aggressive")
    challenge_ttl            = lookup(local.zone_settings, "challenge_ttl", 1800)
    ciphers                  = lookup(local.zone_settings, "ciphers", ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-ECDSA-CHACHA20-POLY1305", "AES128-GCM-SHA256", "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-CHACHA20-POLY1305"])
    cname_flattening         = lookup(local.zone_settings, "cname_flattening", "flatten_at_root")
    development_mode         = lookup(local.zone_settings, "development_mode", "off")
    early_hints              = lookup(local.zone_settings, "early_hints", "off")
    email_obfuscation        = lookup(local.zone_settings, "email_obfuscation", "on")
    hotlink_protection       = lookup(local.zone_settings, "hotlink_protection", "off")
    http2                    = lookup(local.zone_settings, "http2", "on")
    http3                    = lookup(local.zone_settings, "http3", "on")
    ip_geolocation           = lookup(local.zone_settings, "ip_geolocation", "on")
    ipv6                     = lookup(local.zone_settings, "ipv6", "off")
    max_upload               = lookup(local.zone_settings, "max_upload", 125)
    min_tls_version          = lookup(local.zone_settings, "min_tls_version", "1.0")
    # minify {
    #   css  = "on"
    #   html = "off"
    #   js   = "off"
    # }
    mirage                      = lookup(local.zone_settings, "mirage", "on")
    opportunistic_encryption    = lookup(local.zone_settings, "opportunistic_encryption", "off")
    opportunistic_onion         = lookup(local.zone_settings, "opportunistic_onion", "on")
    origin_error_page_pass_thru = lookup(local.zone_settings, "origin_error_page_pass_thru", "off")
    polish                      = lookup(local.zone_settings, "polish", "lossy")
    prefetch_preload            = lookup(local.zone_settings, "prefetch_preload", "off")
    privacy_pass                = lookup(local.zone_settings, "privacy_pass", "on")
    proxy_read_timeout          = lookup(local.zone_settings, "proxy_read_timeout", "100")
    pseudo_ipv4                 = lookup(local.zone_settings, "pseudo_ipv4", "off")
    rocket_loader               = lookup(local.zone_settings, "rocket_loader", "off")
    security_header {
      enabled            = lookup(local.zone_settings.security_header, "enabled", false)
      include_subdomains = lookup(local.zone_settings.security_header, "include_subdomains", false)
      max_age            = lookup(local.zone_settings.security_header, "max_age", 0)
      nosniff            = lookup(local.zone_settings.security_header, "nosniff", false)
      preload            = lookup(local.zone_settings.security_header, "preload", false)
    }
    security_level              = lookup(local.zone_settings, "security_level", "medium")
    server_side_exclude         = lookup(local.zone_settings, "server_side_exclude", "on")
    sort_query_string_for_cache = lookup(local.zone_settings, "sort_query_string_for_cache", "off")
    ssl                         = lookup(local.zone_settings, "ssl", "strict")
    tls_1_3                     = lookup(local.zone_settings, "tls_1_3", "zrt")
    tls_client_auth             = lookup(local.zone_settings, "tls_client_auth", "off")
    true_client_ip_header       = lookup(local.zone_settings, "true_client_ip_header", "on")
    waf                         = lookup(local.zone_settings, "waf", "off")
    websockets                  = lookup(local.zone_settings, "websockets", "on")
    zero_rtt                    = lookup(local.zone_settings, "zero_rtt", "on")
  }
}

