# Configure the Cloudflare provider using the required_providers stanza
# required with Terraform 0.13 and beyond. You may optionally use version
# directive to prevent breaking changes occurring unannounced.
terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.5"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.1"
    }
  }
}

provider "cloudflare" {}