# Read the input YAML file for security configuration and decode the content into local variables  
variable "account_id" {
  type        = string
  description = "Cloudflare account ID"
  validation {
    condition     = can(regex("^[a-z0-9]{32}$", var.account_id))
    error_message = "The Cloudflare account ID must be valid that has only 32 characters from a-z and 0-9."
  }
}

variable "SPLUNK_AUTH_TOKEN" {
  type        = string
  description = "Splunk HTTP Event Collector token"
}

variable "LOGPUSH_DESTINATION_CONF" {
  type        = string
  description = "Logpush Destination URL configuation read from vault as json key/value pair via env var"
  sensitive   = true
}
