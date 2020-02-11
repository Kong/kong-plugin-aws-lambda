local typedefs = require "kong.db.schema.typedefs"

local REGIONS = {
  "ap-northeast-1", "ap-northeast-2",
  "ap-south-1",
  "ap-southeast-1", "ap-southeast-2",
  "ca-central-1",
  "cn-north-1",
  "cn-northwest-1",
  "eu-central-1",
  "eu-north-1",
  "eu-west-1", "eu-west-2", "eu-west-3",
  "me-south-1",
  "sa-east-1",
  "us-east-1", "us-east-2",
  "us-gov-west-1",
  "us-west-1", "us-west-2",
}

local function keyring_enabled()
  local ok, enabled = pcall(function()
    return kong.configuration.keyring_enabled
  end)

  return ok and enabled or nil
end

-- symmetrically encrypt IAM access keys, if configured. this is available
-- in Kong Enterprise: https://docs.konghq.com/enterprise/1.3-x/db-encryption/
local ENCRYPTED = keyring_enabled()

return {
  name = "aws-lambda",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
      type = "record",
      fields = {
        { timeout = {
          type = "number",
          required = true,
          default = 60000,
        } },
        { keepalive = {
          type = "number",
          required = true,
          default = 60000,
        } },
        { aws_key = {
          type = "string",
          encrypted = ENCRYPTED,
        } },
        { aws_secret = {
          type = "string",
          encrypted = ENCRYPTED,
        } },
        { aws_region = {
          type = "string",
          required = true,
          one_of = REGIONS
        } },
        { function_name = {
          type = "string",
          required = true,
        } },
        { qualifier = {
          type = "string",
        } },
        { invocation_type = {
          type = "string",
          required = true,
          default = "RequestResponse",
          one_of = { "RequestResponse", "Event", "DryRun" }
        } },
        { log_type = {
          type = "string",
          required = true,
          default = "Tail",
          one_of = { "Tail", "None" }
        } },
        { port = typedefs.port { default = 443 }, },
        { unhandled_status = {
          type = "integer",
          between = { 100, 999 },
        } },
        { forward_request_method = {
          type = "boolean",
          default = false,
        } },
        { forward_request_uri = {
          type = "boolean",
          default = false,
        } },
        { forward_request_headers = {
          type = "boolean",
          default = false,
        } },
        { forward_request_body = {
          type = "boolean",
          default = false,
        } },
        { is_proxy_integration = {
          type = "boolean",
          default = false,
        } },
        { awsgateway_compatible = {
          type = "boolean",
          default = false,
        } },
        { proxy_scheme = {
          type = "string",
          one_of = { "http", "https" }
        } },
        { proxy_url = typedefs.url },
        { skip_large_bodies = {
          type = "boolean",
          default = true,
        } },
      }
    },
  } },
  entity_checks = {
    { mutually_required = { "config.aws_key", "config.aws_secret" } },
    { mutually_required = { "config.proxy_scheme", "config.proxy_url" } },
  }
}
