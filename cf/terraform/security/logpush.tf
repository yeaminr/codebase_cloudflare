# Logpush Job configuration for Cloudflare
# Ref: https://registry.terraform.io/providers/cloudflare/cloudflare/4.52.0/docs/resources/logpush_job

resource "random_uuid" "splunk_channel_id" {} # random_uuid.splunk_channel_id.result

resource "cloudflare_logpush_job" "splunk_jobs" {
  for_each = {
    for logpush_job in toset(local.logpush_job_settings) : logpush_job.name => logpush_job
  }
  zone_id          = data.cloudflare_zone.zone.id
  name             = each.value.name
  enabled          = each.value.enabled
  destination_conf = "splunk://${each.value.splunk_destination_url}?channel=${random_uuid.splunk_channel_id.result}&insecure-skip-verify=${each.value.splunk_insecure_skip_verify}&sourcetype=${each.value.splunk_source_type}&header_Authorization=Splunk%20${var.SPLUNK_AUTH_TOKEN}"
  dataset          = each.value.dataset
  output_options {
    field_names = each.value.output_field_names
    # for now we should not customise batch_prefix, batch_suffix or record_prefix
    # batch_prefix = lookup(each.value.output_options, "batch_prefix", null)
    # batch_suffix = lookup(each.value.output_options, "batch_suffix", null)
    # record_prefix = lookup(each.value.output_options, "record_prefix", null)
    record_suffix    = lookup(each.value, "output_record_suffix", null)
    cve20214428      = lookup(each.value, "output_cve20214428", null)
    output_type      = lookup(each.value, "output_type", null)
    timestamp_format = lookup(each.value, "output_timestamp_format", null)
  }
}


resource "cloudflare_logpush_job" "logpush_pipeline_jobs" {
  for_each = {
    for logpush_job in toset(local.logpush_pipeline_job_settings) : logpush_job.name => logpush_job
  }
  zone_id          = data.cloudflare_zone.zone.id
  name             = each.value.name
  enabled          = lookup(each.value, "enabled", true)
  destination_conf = lookup(jsondecode(var.LOGPUSH_DESTINATION_CONF), each.value.destination_conf_key, null)
  dataset          = each.value.dataset
  max_upload_bytes = lookup(each.value, "max_upload_bytes", 50000000) # 50MB
  output_options {
    field_names = each.value.output_field_names
    # for now we should not customise batch_prefix, batch_suffix or record_prefix
    # batch_prefix = lookup(each.value.output_op1tions, "batch_prefix", null)
    # batch_suffix = lookup(each.value.output_options, "batch_suffix", null)
    # record_prefix = lookup(each.value.output_options, "record_prefix", null)
    record_suffix    = lookup(each.value, "output_record_suffix", null)
    cve20214428      = lookup(each.value, "output_cve20214428", null)
    output_type      = lookup(each.value, "output_type", null)
    timestamp_format = lookup(each.value, "output_timestamp_format", null)
  }
}
