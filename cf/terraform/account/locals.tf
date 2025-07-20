# Read the YAML input file
locals {
  account_input  = yamldecode(file("${path.module}/account_parameters.yml"))
  noname_configs = local.account_input.noname_configs                            # Noname - Required field
  cf_ip_lists    = lookup(local.account_input, "cf_ip_lists", [])  # IP lists
  cf_asn_lists   = lookup(local.account_input, "cf_asn_lists", []) # ASN lists
  worker_configs = try(local.account_input.worker_configs, null) != null && can(length(local.account_input.worker_configs)) ? [for worker_config in local.account_input.worker_configs : {
    script_name        = worker_config.script_name
    script_file        = worker_config.script_file
    plain_text_binding = lookup(worker_config, "plain_text_binding", [])
  }] : []

  # Convert workers_secret format
  # From [{\"worker_name\"=\"noname-worker\",\"secret_key\"=\"SOURCE_KEY\",\"secret_text\"=\"SECRET_TEXT\"}]
  # To { worker_name = [{\"secret_key\"=\"SOURCE_KEY\",\"secret_text\"=\"SECRET_TEXT\"}]}
  workers_secret = {
    for ws in toset([for i in var.workers_secret : i.worker_name]) : ws => [for item in var.workers_secret : {
      secret_key  = item.secret_key,
      secret_text = item.secret_text
    }]
  }
}
