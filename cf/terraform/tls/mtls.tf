# # Set Cloudflare Access Application Settings
# # https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/access_application

# resource "cloudflare_access_application" "cba_mtls_settings" {
#   app_launcher_visible       = true
#   auto_redirect_to_identity  = false
#   domain                     = "autopoc1.terryform.com/mtls"
#   enable_binding_cookie      = false
#   http_only_cookie_attribute = true
#   name                       = "API Gateway"
# # self_hosted_domains        = ["autopoc1.terryform.com/mtls"]
#   service_auth_401_redirect  = true
#   session_duration           = "0s"
#   type                       = "self_hosted"
#   zone_id                    = "${data.cloudflare_zone.zone.id}"
# }

# # Set Access Policies

# resource "cloudflare_access_policy" "test_policy" {
#   application_id = "${cloudflare_access_application.cba_mtls_settings.id}"
#   zone_id        = "${data.cloudflare_zone.zone.id}"
#   name           = "mTLS Authentication"
#   precedence     = "1"
#   decision       = "non_identity"

#   include {
#     certificate = "true"
#   }

#   require {
#     common_name = "Mastercard"
#   }
# }

# # Set Access MTLS Certificate Settings
# # https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/resources/mtls_certificate

# resource "cloudflare_access_mutual_tls_certificate" "Mastercard_Root_CA" {
#   zone_id              = "${data.cloudflare_zone.zone.id}"
#   name                 = "Mastercard Root CA"
#   certificate          = var.mastercard_ca_pem
#   associated_hostnames = [var.mastercard_hostname]
# }

# resource "cloudflare_access_mutual_tls_certificate" "Payment_GW_Root_CA" {
#   zone_id              = "${data.cloudflare_zone.zone.id}"
#   name                 = "Payment GW Root CA"
#   certificate          = var.payment_ca_pem
#   associated_hostnames = [var.payment_hostname]
# }

# resource "cloudflare_access_mutual_tls_certificate" "Mastercard_Bundle_CA" {
#   zone_id              = "${data.cloudflare_zone.zone.id}"
#   name                 = "Mastercard Intermediate and Root CA"
#   certificate          = var.mastercard_bundle_pem
#   associated_hostnames = [var.mcard_bundle_hostname]
# }
