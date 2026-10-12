variable "host_id" {
  type        = string
  description = "Fleet host id. Set SYSTEMAPI_URL and SYSTEMAPI_API_KEY in the environment. Do not declare or pass an API key as a Terraform variable."

  validation {
    condition     = length(var.host_id) > 0
    error_message = "host_id is required."
  }
}
