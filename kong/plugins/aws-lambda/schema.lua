local typedefs = require "kong.db.schema.typedefs"
local null     = ngx.null


local function keyring_enabled()
  local ok, enabled = pcall(function()
    return kong.configuration.keyring_enabled
  end)

  return ok and enabled or nil
end

local function is_nonempty(value)
  if value == nil
     or value == null
     or (type(value) == "table" and not next(value))
     or (type(value) == "string" and value == "") then
    return false
  end

  return true
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
        { aws_region = typedefs.host },
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
        { host = typedefs.host },
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
        { base64_encode_body = {
          type = "boolean",
          default = true,
        } },
      }
    },
  } },
  entity_checks = {
    { mutually_required = { "config.aws_key", "config.aws_secret" } },
    { mutually_required = { "config.proxy_scheme", "config.proxy_url" } },
    { custom_entity_check = {
      field_sources = { "config" },
      fn = function(entity)
        local config = entity.config
        if is_nonempty(config.host) and is_nonempty(config.aws_region) then
          return nil, "At least one of 'config.aws_region', 'config.host' should not be set"
        end
        return true
      end,
    } },
  }
}
