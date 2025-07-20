# Create WAF Rate Limiting Rules
# Ref: https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/ruleset#nestedatt--rules--action_parameters--response_fields
# Ref: https://developers.cloudflare.com/terraform/additional-configurations/rate-limiting-rules/
# Ref: https://registry.terraform.io/providers/cloudflare/cloudflare/4.43.0/docs/resources/ruleset#requests_to_origin
# Ref: https://github.com/cloudflare/terraform-provider-cloudflare/blob/master/internal/framework/service/rulesets/resource_test.go#L3457-L3490

# Create WAF Rate Limiting Ruleset
resource "cloudflare_ruleset" "rate_limit_ruleset" {
  zone_id     = data.cloudflare_zone.zone.id
  name        = "Rate Limit Ruleset"
  description = "Rate Limit Ruleset"
  kind        = "zone"
  phase       = "http_ratelimit"

  dynamic "rules" {
    for_each = local.waf_rate_limiting_ruleset.rules
    content {
      action = lookup(rules.value, "action", "block")
      ratelimit {
        characteristics = [
          "cf.colo.id",
          "ip.src"
        ]
        period              = lookup(rules.value, "period", 60)
        requests_per_period = lookup(rules.value, "requests_per_period", 100)
        mitigation_timeout  = lookup(rules.value, "mitigation_timeout", 60)
        requests_to_origin  = lookup(rules.value, "requests_to_origin", true)
        counting_expression = lookup(rules.value, "counting_expression", null)
      }
      expression  = rules.value.expression
      description = rules.value.description
      enabled     = lookup(rules.value, "enabled", true)
    }
  }

}
