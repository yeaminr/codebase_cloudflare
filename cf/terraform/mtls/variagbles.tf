variable "account_id" {
  type        = string
  description = "Cloudflare account ID"
  validation {
    condition     = can(regex("^[a-z0-9]{32}$", var.account_id))
    error_message = "The Cloudflare account ID must be valid that has only 32 characters from a-z and 0-9."
  }
}

variable "mtls_details" {
  type = list(object({
    name = string             # name in tenant YAML file
    zero_trust_name = string  # name given in Cloudflare Zero Trust
    cert_id = string          # id of cert in Cloudflare Zero Trust
    domain = string          # domain for which the cert is valid
  }))
  description = "List of mTLS details to be managed"
}