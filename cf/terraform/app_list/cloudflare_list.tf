# cloudflare_list.tf
# Ref: https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/list

# The cloudflare_list can be of 4 kinds as per the above reference - IP addresses, ASNs, hostnames or redirects

resource "cloudflare_list" "cf_ip_lists" {
  for_each = {
    for cf_lst in toset(local.cf_ip_lists) : cf_lst.name => cf_lst
  }
  account_id  = var.account_id
  name        = each.value.name
  description = each.value.description
  kind        = "ip"
  dynamic "item" {
    for_each = toset(each.value.ip)
    content {
      value {
        ip = replace(item.value, "/32", "")
      }
    }
  }
}

resource "cloudflare_list" "cf_asn_lists" {
  for_each = {
    for cf_lst in toset(local.cf_asn_lists) : cf_lst.name => cf_lst
  }
  account_id  = var.account_id
  name        = each.value.name
  description = each.value.description
  kind        = "asn"
  dynamic "item" {
    for_each = toset(each.value.asn)
    content {
      value {
        asn = item.value
      }
    }
  }
}
