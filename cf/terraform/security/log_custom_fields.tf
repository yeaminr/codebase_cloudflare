# Create WAF Custom Rules
# Ref: https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/ruleset
# Ref: https://developers.cloudflare.com/terraform/additional-configurations/waf-custom-rules/


# Create WAF Custom Rules
resource "cloudflare_ruleset" "log_custom_fields" {
  for_each    = local.log_custom_fields
  zone_id     = data.cloudflare_zone.zone.id
  name        = "HTTP Log Custom Fields"
  description = "HTTP Log Custom Fields"
  kind        = "zone"
  phase       = "http_log_custom_fields"

  rules {
    action = lookup(each.value, "action", "log_custom_field")
    action_parameters {
      request_fields = each.value.action_parameters.request_fields
    }
    expression  = each.value.expression
    description = each.value.description
    enabled     = lookup(each.value, "enabled", true)
  }
}
