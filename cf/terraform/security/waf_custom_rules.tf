# Create WAF Custom Rules
# Ref: https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/ruleset
# Ref: https://developers.cloudflare.com/terraform/additional-configurations/waf-custom-rules/


# Create WAF Custom Rules
resource "cloudflare_ruleset" "waf_custom_ruleset" {
  zone_id     = data.cloudflare_zone.zone.id
  name        = "Zone WAF Custom Ruleset"
  description = "WAF Custom Rules"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  dynamic "rules" {
    for_each = local.waf_custom_ruleset.rules
    content {
      action      = lookup(rules.value, "action", "block")
      expression  = rules.value.expression
      description = rules.value.description
      enabled     = lookup(rules.value, "enabled", true)
      dynamic "action_parameters" {
        for_each = lookup(rules.value, "action_parameters", null) != null ? [1] : []
        content {
          phases   = lookup(rules.value.action_parameters, "phases", null)
          products = lookup(rules.value.action_parameters, "products", null)
          ruleset  = lookup(rules.value.action_parameters, "ruleset", null)
          dynamic "response" {
            for_each = lookup(rules.value.action_parameters, "response", null) != null ? [1] : []
            content {
              content      = lookup(rules.value.action_parameters.response, "content", null)
              content_type = lookup(rules.value.action_parameters.response, "content_type", null)
              status_code  = lookup(rules.value.action_parameters.response, "status_code", null)
            }
          }
        }
      }
      dynamic "logging" {
        for_each = lookup(rules.value, "logging", null) != null ? [1] : []
        content {
          enabled = lookup(rules.value.logging, "enabled", true)
        }
      }
    }
  }

}
