# Terraform driver

Reads one host from the SystemAPI fleet API through Terraform's built-in `external` data source. This is not a terraform-plugin-framework provider.

Set these in the environment before `terraform plan` or `terraform apply`:

- `SYSTEMAPI_URL` - API base URL. A single trailing slash is stripped.
- `SYSTEMAPI_API_KEY` - sent only as the `X-API-Key` header.

`SYSTEMAPI_TENANT` is optional and is not printed. Do not put the API key in a `.tf` file, a `TF_VAR_`, or on the command line.

```hcl
module "host" {
  source  = "./drivers/terraform"
  host_id = "your-host-id"
}
```

Outputs are `host_id`, `hostname`, and `status`.
