local os = require "os"
local http  = require "resty.http"
local io = require "io"
local json  = require "cjson"
local parse_date = require("luatz").parse.rfc_3339
local aws_v4 = require "kong.plugins.aws-lambda.v4"
local url = require "socket.url"

local ngx_now = ngx.now
local log = kong.log

local DEFAULT_SERVICE_REQUEST_TIMEOUT = 5000
local DEFAULT_SESSION_DURATION_SECONDS = 3600

local WEB_IDENTITY_TOKEN_FILE = os.getenv ("AWS_WEB_IDENTITY_TOKEN_FILE")
local ROLE_ARN = os.getenv("AWS_ROLE_ARN")
local DEFAULT_ROLE_SESSION_NAME = "kong-plugin-lambda-web-identity-token"

local function create_web_identity_provider(externalConfig)

  local self = { config = externalConfig }

  local function convert_params_to_query(params)
    local unescaped_params = {}
    for k, v in pairs(params) do
      table.insert(unescaped_params, url.escape(k) .. '=' .. url.escape(v))
    end
    return table.concat(unescaped_params, '&')
  end
  --
  -- PRIVATE FUNCTIONS
  --
  local function fetch_assume_role_credentials(sts_client, sts_host, role_arn_to_assume, aws_region,
                                               access_key, secret_key, session_token, role_session_name)
    log.debug('[iam web identity] fetch credentials for to assume Role [', role_arn_to_assume, ']')

    local queryParams = {
        ["Action"]           = "AssumeRole",
        ["Version"]          = "2011-06-15",
        ["RoleArn"]          = role_arn_to_assume,
        ["DurationSeconds"]  = DEFAULT_SESSION_DURATION_SECONDS,
        ["RoleSessionName"]  = role_session_name
    }

    local opts = {
      region = aws_region,
      service = "sts",
      method = "GET",
      headers = {
        ["Accept"] = "application/json",
        ["Content-Type"] = "application/json",
        ["X-Amz-Security-Token"] = session_token
      },
      path = '/',
      host = sts_host,
      port = 443,
      access_key = access_key,
      secret_key = secret_key,
      query = convert_params_to_query(queryParams)
    }

    local request, aws_sign_err = aws_v4(opts)
    if aws_sign_err then
      return nil, 'Unable to build request to get credentials for the assumeRole [' .. role_arn_to_assume .. '] - error :'.. tostring(aws_sign_err)
    end

    local res, err = sts_client:request {
      method = "POST",
      path = request.url,
      body = request.body,
      headers = request.headers
    }
    if not res then
      return nil, 'Unable to get credentials for the assumeRole [' .. role_arn_to_assume .. ']' .. tostring(err)
    end

    local jsonCredentials = json.decode(res:read_body()).Credentials
    local credentials = {
      access_key    = jsonCredentials.AccessKeyId,
      secret_key    = jsonCredentials.SecretAccessKey,
      session_token = jsonCredentials.SessionToken,
      expiration    = parse_date(jsonCredentials.Expiration):timestamp()
    }

    return credentials, nil, credentials.expiration - ngx_now()
  end

  local function fetch_web_identity_credentials()
    -- retrieve web identity token from file
    local file = io.open(WEB_IDENTITY_TOKEN_FILE, "r")
    local web_identity_token = file:read("*all")
    file:close()

    -- region is optional but it's better to reduce latency
    local region = self.config.aws_region or ''
    local sts_url
    if self.config.aws_region then
      sts_url = 'sts.' .. region .. '.amazonaws.com'
    else
      sts_url = 'sts.amazonaws.com'
    end

    local sts_client = http.new()
    sts_client:set_timeout(DEFAULT_SERVICE_REQUEST_TIMEOUT)

    local ok, connectionErr = sts_client:connect(sts_url, 443)
    if not ok then
      return nil, 'Unable to connect to STS server ' .. sts_url .. ', ' .. tostring(connectionErr)
    end

    local queryParams = {
      ["Action"]           = "AssumeRoleWithWebIdentity",
      ["Version"]          = "2011-06-15",
      ["RoleArn"]          = ROLE_ARN,
      ["DurationSeconds"]  = DEFAULT_SESSION_DURATION_SECONDS,
      ["WebIdentityToken"] = web_identity_token,
      ["RoleSessionName"]  = DEFAULT_ROLE_SESSION_NAME
    }
    if self.config.aws_role_session_name then
      -- override assume role for cross account
      queryParams["RoleSessionName"] = self.config.aws_role_session_name
    end

    log.debug('[iam web identity] fetch credentials sts url [', sts_url, '] - RoleSessionName [', queryParams["RoleSessionName"], ']')

    local res, reqErr = sts_client:request({
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

    if self.config.aws_cross_account_role then
      -- need to assume the cross account role to call the lambda
      credentials = fetch_assume_role_credentials(sts_client,sts_url, self.config.aws_cross_account_role, region,
        credentials.access_key, credentials.secret_key, credentials.session_token, queryParams["RoleSessionName"])
    end

    sts_client:close()
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


-- Get the ECS provider if it's configuredspec/plugins/aws-lambda/07-iam-web-identity-token-credentials_spec.lua
local get_provider = function (config)
  if not (ROLE_ARN and WEB_IDENTITY_TOKEN_FILE) then
    return nil
  end

  return create_web_identity_provider(config)
end


return {
  get_provider = get_provider
}
