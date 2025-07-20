output "mtls_details" {
  value = [for k, mtls in terraform_data.mtls : mtls.output]
}