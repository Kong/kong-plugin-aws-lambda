local os = require "os"
local http  = require "resty.http"
local io = require "io"
local json  = require "cjson"
local parse_date = require("luatz").parse.rfc_3339
local ngx_now = ngx.now

local log = kong.log

local DEFAULT_SERVICE_REQUEST_TIMEOUT = 5000

local WEB_IDENTITY_TOKEN_FILE = os.getenv ("AWS_WEB_IDENTITY_TOKEN_FILE")
local ROLE_ARN = os.getenv("AWS_ROLE_ARN")


local function create_web_identity_provider(externalConfig)

  local self = { config = externalConfig }

  --
  -- PRIVATE FUNCTIONS
  --
  local function fetch_web_identity_credentials()
    -- retrieve web identity token from file
    local file = io.open(WEB_IDENTITY_TOKEN_FILE, "r")
    local web_identity_token = file:read("*all")
    file:close()

    -- region is optional but it's better to reduce latency
    local region = ''
    if self.config.aws_region then
      region = self.config.aws_region .. '.'
    end
    local host = "sts." .. region .. "amazonaws.com"

    local client = http.new()
    client:set_timeout(DEFAULT_SERVICE_REQUEST_TIMEOUT)

    local ok, connectionErr = client:connect(host, 443)
    if not ok then
      return nil, 'Unable to connect to STS server ' .. host .. ', ' .. tostring(connectionErr)
    end

    local queryParams = {
        ["Action"]          = "AssumeRoleWithWebIdentity",
        ["Version"]         = "2011-06-15",
        ["RoleArn"]         = ROLE_ARN,
        ["DurationSeconds"] = "3600",
        ["ExternalId"]      = "kong-plugin-lambda",
        ["WebIdentityToken"]       = web_identity_token,
        ["RoleSessionName"]       = "kong-plugin-lambda"
    }
    if self.config.aws_role_session_name then
      -- override assume role for cross account
      queryParams["RoleSessionName"] = self.config.aws_role_session_name
    end

    local res, reqErr = client:request({
      method = "GET",
      path   = "/",
      headers = {
        ["Accept"] = "application/json"
      },
      queryParams
    })
    if not res then
      return nil, "Unable to get STS credentials" .. tostring(reqErr)
    end

    -- extract data from credentials
    local jsonCredentials = json.decode(res:read_body()).Credentials
    local credentials = {
      access_key    = jsonCredentials.AccessKeyId,
      secret_key    = jsonCredentials.SecretAccessKey,
      session_token = jsonCredentials.SessionToken,
      expiration    = parse_date(jsonCredentials.Expiration):timestamp()
    }

    return credentials, nil, credentials.expiration - ngx_now()
  end

  --
  -- PUBLIC FUNCTIONS
  --
  local fetch_credentials_logged = function()
    local creds, err, ttl = fetch_web_identity_credentials()
    if creds then
      return creds, err, ttl
    end
    log.err(err)
    return nil, err, nil
  end

  return {
    fetch_credentials = fetch_credentials_logged
  }
end


-- Get the ECS provider if it's configuredspec/plugins/aws-lambda/06-iam-web-identity-token-credentials_spec.lua
local get_provider = function (config)
  if not (ROLE_ARN and WEB_IDENTITY_TOKEN_FILE) then
    return nil
  end

  return create_web_identity_provider(config)
end


return {
  get_provider = get_provider
}
