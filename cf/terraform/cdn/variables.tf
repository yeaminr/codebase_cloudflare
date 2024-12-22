variable "cdn_config_file" {
  type        = string
  description = "Path to the CDN configuration yml file"
  default     = "cdn_parameters.yml"
}

variable "zone_config_file" {
  type        = string
  description = "Path to the zone configuration yml file"
  default     = "zone_parameters.yml"
}

variable "account_id" {
  type        = string
  description = "Cloudflare account ID"
  validation {
    condition     = can(regex("^[a-z0-9]{32}$", var.account_id))
    error_message = "The Cloudflare account ID must be valid that has only 32 characters from a-z and 0-9."
  }
}
