# cloudflare_list.tf
# Ref: https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/list
# Ref: https://developer.hashicorp.com/terraform/language/meta-arguments/for_each

resource "cloudflare_list" "policy_name_rate_control_bypass_list_terraform" {
  account_id  = var.account_id
  name        = "policy_name_rate_control_bypass_list_tf"
  description = "Policy Name Rate Control Bypass List"
  kind        = "ip"

  # Ref: https://developer.hashicorp.com/terraform/language/expressions/dynamic-blocks
  dynamic "item" {
    for_each = toset(local.policy_name_rate_control_bypass_list)
    content {
      value {
        ip = item.value
      }
    }
  }

}

resource "cloudflare_list" "rate_control_bypass_global_list_terraform" {
  account_id  = var.account_id
  name        = "rate_control_bypass_global_list_tf"
  description = "Rate Control Bypass Global List"
  kind        = "ip"

  dynamic "item" {
    for_each = toset(local.rate_control_bypass_global_list)
    content {
      value {
        ip = item.value
      }
    }
  }

}

resource "cloudflare_list" "group_wide_whitelist_terraform" {
  account_id  = var.account_id
  name        = "group_wide_whitelist_tf"
  description = "Account level IP whitelist"
  kind        = "ip"

  dynamic "item" {
    for_each = toset(local.group_wide_whitelist)
    content {
      value {
        ip = item.value
      }
    }
  }

}

resource "cloudflare_list" "group_wide_blacklist_terraform" {
  account_id  = var.account_id
  name        = "group_wide_blacklist_tf"
  description = "Account level IP blacklist"
  kind        = "ip"

  dynamic "item" {
    for_each = toset(local.group_wide_blacklist)
    content {
      value {
        ip = item.value
      }
    }
  }

}
