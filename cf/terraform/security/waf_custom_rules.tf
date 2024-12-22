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
    }
  }

}
