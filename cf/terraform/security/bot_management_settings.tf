resource "cloudflare_bot_management" "bot_management" {
  zone_id           = data.cloudflare_zone.zone.id
  enable_js         = lookup(local.bot_management_settings, "enable_js", null)
  auto_update_model = lookup(local.bot_management_settings, "auto_update_model", null)
}
