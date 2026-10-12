# The API key stays in SYSTEMAPI_API_KEY. It is not a variable or a program argument.
data "external" "host" {
  program = ["node", "${path.module}/../../cli/systemapi.js", "host-json", "--host", var.host_id]
}

output "host_id" {
  value = data.external.host.result.host_id
}

output "hostname" {
  value = data.external.host.result.hostname
}

output "status" {
  value = data.external.host.result.status
}
