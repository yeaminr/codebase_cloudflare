# Read the YAML input file
locals {
  app_list_param = try(yamldecode(file("${path.module}/app_list_parameters.yml")), {})
  cf_ip_lists    = lookup(local.app_list_param, "cf_ip_lists", [])
  cf_asn_lists   = lookup(local.app_list_param, "cf_asn_lists", [])
}
