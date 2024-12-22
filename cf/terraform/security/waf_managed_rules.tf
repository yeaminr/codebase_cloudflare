# Create WAF Managed Ruleset
# Re: https://developers.cloudflare.com/terraform/additional-configurations/waf-managed-rulesets/
# Ref: https://developers.cloudflare.com/ruleset-engine/managed-rulesets/create-exception/#skip-all-remaining-rules
# Ref: https://github.com/cloudflare/terraform-provider-cloudflare/blob/master/internal/framework/service/rulesets/resource_test.go#L2969-L2980
# Ref: https://developers.cloudflare.com/terraform/additional-configurations/waf-managed-rulesets/#configure-overrides
# Ref: https://developers.cloudflare.com/ruleset-engine/managed-rulesets/override-managed-ruleset/#ruleset-override-example

# Configure a ruleset at the zone level for the "http_request_firewall_managed" phase
resource "cloudflare_ruleset" "waf_managed_ruleset" {
  zone_id     = data.cloudflare_zone.zone.id
  name        = "Managed WAF entry point ruleset"
  description = "Zone-level WAF Managed Ruleset config"
  kind        = "zone"
  phase       = "http_request_firewall_managed"

  # Exception rule - Skip execution of the entire Cloudflare Managed Ruleset for specific URLs
  rules {
    action = local.waf_managed_ruleset.exceptions.action
    action_parameters {
      # rulesets = [for rule in local.waf_managed_ruleset.rules : rule.action_parameters.id]
      ruleset = "current"
    }
    expression  = local.waf_managed_ruleset.exceptions.expression
    description = local.waf_managed_ruleset.exceptions.description # Skip Cloudflare Managed ruleset
    enabled     = local.waf_managed_ruleset.exceptions.enabled
    logging {
      enabled = true
    }
  }

  # Cloudflare Managed Ruleset
  dynamic "rules" {
    for_each = local.waf_managed_ruleset.rules
    content {
      action = rules.value.action
      action_parameters {
        id      = rules.value.action_parameters.id
        version = lookup(rules.value.action_parameters, "version", "latest")
        overrides {
          enabled = lookup(rules.value.overrides, "enabled", null)
          action  = rules.value.overrides.action
          dynamic "rules" { // this "rules" is not the above "rules", this is nested "rules" of overrides. Ref: https://developers.cloudflare.com/terraform/additional-configurations/waf-managed-rulesets/#configure-overrides
            for_each = rules.value.overrides.rules
            content {
              id      = lookup(rules.value, "rule_id", null)
              action  = rules.value.action
              enabled = rules.value.enabled
            }
          }
        }
      }
      expression  = rules.value.expression
      description = rules.value.description
      enabled     = rules.value.enabled
    }
  }

}
