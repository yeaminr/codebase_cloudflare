# # Origin Certificates
# resource "tls_private_key" "example" {
#   algorithm = "RSA"
# }

# resource "tls_cert_request" "example" {
#   private_key_pem = tls_private_key.example.private_key_pem

#   subject {
#     common_name  = ""
#     organization = "Terraform Test"
#   }
# }

# resource "cloudflare_origin_ca_certificate" "example" {
#   csr                = tls_cert_request.example.cert_request_pem
#   hostnames          = ["example.com"]
#   request_type       = "origin-rsa"
#   requested_validity = 7
# }

# # Authenticated Origin Pulls
# resource "cloudflare_authenticated_origin_pulls" "my_aop" {
#   zone_id = "0da42c8d2132a9ddaf714f9e7c920711"
#   enabled = true
# }

# # Per-Zone Authenticated Origin Pulls
# resource "cloudflare_authenticated_origin_pulls_certificate" "my_per_zone_aop_cert" {
#   zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
#   certificate = "-----INSERT CERTIFICATE-----"
#   private_key = "-----INSERT PRIVATE KEY-----"
#   type        = "per-zone"
# }

# resource "cloudflare_authenticated_origin_pulls" "my_per_zone_aop" {
#   zone_id                                = "0da42c8d2132a9ddaf714f9e7c920711"
#   authenticated_origin_pulls_certificate = cloudflare_authenticated_origin_pulls_certificate.my_per_zone_aop_cert.id
#   enabled                                = true
# }

# # Per-Hostname Authenticated Origin Pulls
# resource "cloudflare_authenticated_origin_pulls_certificate" "my_per_hostname_aop_cert" {
#   zone_id     = "0da42c8d2132a9ddaf714f9e7c920711"
#   certificate = "-----INSERT CERTIFICATE-----"
#   private_key = "-----INSERT PRIVATE KEY-----"
#   type        = "per-hostname"
# }

# resource "cloudflare_authenticated_origin_pulls" "my_per_hostname_aop" {
#   zone_id                                = "0da42c8d2132a9ddaf714f9e7c920711"
#   authenticated_origin_pulls_certificate = cloudflare_authenticated_origin_pulls_certificate.my_per_hostname_aop_cert.id
#   hostname                               = "aop.example.com"
#   enabled                                = true
# }