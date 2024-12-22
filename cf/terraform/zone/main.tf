locals {
  zone_input = yamldecode(file("${path.module}/zone_parameters.yml"))
  zone_name  = local.zone_input.fqdn
}

resource "cloudflare_zone" "cba_zone" {
  account_id = var.account_id
  paused     = false
  plan       = "enterprise"
  type       = "partial"
  zone       = local.zone_name
  lifecycle {
    prevent_destroy = true
  }
}

output "zone_id" {
  value = cloudflare_zone.cba_zone.id
}

output "verification_keys" {
  value = cloudflare_zone.cba_zone.verification_key
}
