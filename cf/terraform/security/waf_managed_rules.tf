# Create WAF Managed Ruleset
# Ref: https://developers.cloudflare.com/terraform/additional-configurations/waf-managed-rulesets/
# Ref: https://developers.cloudflare.com/ruleset-engine/managed-rulesets/create-exception/#skip-all-remaining-rules
# Ref: https://github.com/cloudflare/terraform-provider-cloudflare/blob/master/internal/framework/service/rulesets/resource_test.go#L2969-L2980
# Ref: https://developers.cloudflare.com/terraform/additional-configurations/waf-managed-rulesets/#configure-overrides
# Ref: https://developers.cloudflare.com/ruleset-engine/managed-rulesets/override-managed-ruleset/#ruleset-override-example
# Ref: https://registry.terraform.io/providers/cloudflare/cloudflare/4.52.0/docs/resources/ruleset#score_threshold-1

# Configure a ruleset at the zone level for the "http_request_firewall_managed" phase
resource "cloudflare_ruleset" "waf_managed_ruleset" {
  zone_id     = data.cloudflare_zone.zone.id
  name        = "Managed WAF entry point ruleset"
  description = "Zone-level WAF Managed Ruleset config"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  # Cloudflare Managed Ruleset
  dynamic "rules" {
    for_each = local.waf_managed_ruleset.rules
    content {
      action = rules.value.action
      action_parameters {
        id      = lookup(rules.value.action_parameters, "id", null)
        ruleset = lookup(rules.value.action_parameters, "ruleset", null) # ruleset and rules are mutually exclusive fields here
        rules = lookup(rules.value.action_parameters, "skip_rules", null) != null ? {
          for skip_rule in rules.value.action_parameters.skip_rules :
          skip_rule.ruleset_id => skip_rule.rule_ids
        } : null

        dynamic "matched_data" {
          for_each = lookup(rules.value.action_parameters, "matched_data", null) != null ? [1] : []
          content {
            public_key = rules.value.action_parameters.matched_data.public_key
          }
        }

        dynamic "overrides" {
          for_each = lookup(rules.value.action_parameters, "overrides", null) != null ? [1] : []
          content {
            enabled = lookup(rules.value.action_parameters.overrides, "enabled", null)
            action  = lookup(rules.value.action_parameters.overrides, "action", null)
            dynamic "rules" { // this "rules" is not the above "rules", this is nested "rules" of overrides. Ref: https://developers.cloudflare.com/terraform/additional-configurations/waf-managed-rulesets/#configure-overrides
              for_each = lookup(rules.value.action_parameters.overrides, "rules", null) != null ? rules.value.action_parameters.overrides.rules : []
              content {
                id                = lookup(rules.value, "rule_id", null)
                action            = lookup(rules.value, "action", null)
                enabled           = lookup(rules.value, "enabled", null)
                score_threshold   = lookup(rules.value, "score_threshold", null)
                sensitivity_level = lookup(rules.value, "sensitivity_level", null)
              }
            }
            dynamic "categories" {
              for_each = lookup(rules.value.action_parameters.overrides, "categories", null) != null ? rules.value.action_parameters.overrides.categories : []
              content {
                category = lookup(categories.value, "category", null)
                enabled  = lookup(categories.value, "enabled", null)
              }
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
      expression  = rules.value.expression
      description = rules.value.description
      enabled     = lookup(rules.value, "enabled", true)
    }
  }

}
