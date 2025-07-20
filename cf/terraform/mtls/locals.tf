locals {
  zone_inputs = yamldecode(file("${path.module}/zone_parameters.yml"))
  zone_name   = local.zone_inputs.fqdn
  mtls_params = yamldecode(file("${path.module}/mtls_parameters.yml"))
  mtls_data = {
    for mtls in var.mtls_details : mtls.name => mtls
  }
}
