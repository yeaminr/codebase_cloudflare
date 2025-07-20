variable "account_id" {
  type        = string
  description = "Cloudflare account ID"
  validation {
    condition     = can(regex("^[a-z0-9]{32}$", var.account_id))
    error_message = "The Cloudflare account ID must be valid that has only 32 characters from a-z and 0-9."
  }
}
