local os = require "os"
local http  = require "resty.http"
local io = require "io"
local json  = require "cjson"
local aws_v4 = require "kong.plugins.aws-lambda.v4"
local utils = require "kong.tools.utils"

local ngx_now = ngx.now
local log = kong.log

local DEFAULT_SESSION_DURATION_SECONDS = 3600

local WEB_IDENTITY_TOKEN_FILE = os.getenv ("AWS_WEB_IDENTITY_TOKEN_FILE")
local ROLE_ARN = os.getenv("AWS_ROLE_ARN")
local DEFAULT_ROLE_SESSION_NAME = "kong-plugin-lambda"

local function create_web_identity_provider(externalConfig)

  local self = { config = externalConfig }

  --
  -- PRIVATE FUNCTIONS
  --
  local function fetch_assume_role_credentials(sts_host, aws_region, assume_role_arn,
                                               access_key, secret_key, session_token, role_session_name)
    log.debug('Try to assume role [', assume_role_arn, ']')

    -- build the url and signature to assume role
    local ar_headers = {
      Accept                    = "application/json",
      ["Content-Type"]          = "application/x-www-form-urlencoded; charset=utf-8",
      ["X-Amz-Security-Token"]  = session_token,
      Host                      = sts_host
    }
    local ar_query_params = {
      Action          = "AssumeRole",
      Version         = "2011-06-15",
      RoleArn         = assume_role_arn,
      DurationSeconds = DEFAULT_SESSION_DURATION_SECONDS,
      RoleSessionName = role_session_name,
    }
    local ar_encoded_query_params = utils.encode_args(ar_query_params)
    local ar_sign_params = {
      region          = aws_region,
      service         = "sts",
      access_key      = access_key,
      secret_key      = secret_key,
      method          = "GET",
      port            = 443,
      headers         = ar_headers,
      query           = ar_encoded_query_params
    }

    local ar_sign_res, ar_sign_err = aws_v4(ar_sign_params)
    if ar_sign_err then
      return nil, 'Unable to build signature to assume role [' .. assume_role_arn .. '] - error :'.. tostring(ar_sign_err)
    end

    -- Call STS to assume role
    local httpc = http.new()
    local ar_res, ar_err = httpc:request_uri(ar_sign_res.url, {
      method = ar_sign_res.method,
      headers = ar_sign_res.headers,
      ssl_verify = false,
    })

    if not ar_res then
      return nil, 'Unable to assume role ' .. assume_role_arn .. ' :' .. tostring(ar_err)
    end
    if ar_res.status ~= 200 then
      return nil, 'Unable to assume the role [' .. assume_role_arn .. '] due to: status [' .. ar_res.status .. '] - reason [' .. ar_res.body .. ']'
    end

    local ar_json_credentials = json.decode(ar_res.body).AssumeRoleResponse.AssumeRoleResult.Credentials
    local ar_credentials = {
      access_key    = ar_json_credentials.AccessKeyId,
      secret_key    = ar_json_credentials.SecretAccessKey,
      session_token = ar_json_credentials.SessionToken,
      expiration    = ar_json_credentials.Expiration
    }

    return ar_credentials, nil, ar_credentials.expiration - ngx_now()
  end

  local function fetch_web_identity_credentials()
    -- retrieve web identity token from file
    local file = io.open('/tmp/aws_token_test', "r")
    local web_identity_token = file:read("*all")
    file:close()

    -- region is optional but it's better to reduce latency
    local region, sts_host
    if self.config.aws_region then
      region = self.config.aws_region
      sts_host = 'sts.' .. region .. '.amazonaws.com'
    else
      region = ''
      sts_host = 'sts.amazonaws.com'
    end

    local role_session_name = self.config.aws_role_session_name or DEFAULT_ROLE_SESSION_NAME
    local wit_query_params = {
      ["Action"]           = "AssumeRoleWithWebIdentity",
      ["Version"]          = "2011-06-15",
      ["RoleArn"]          = ROLE_ARN,
      ["DurationSeconds"]  = 3600,
      ["WebIdentityToken"] = web_identity_token,
      ["RoleSessionName"]  = role_session_name
    }

    local wit_encoded_query_params = utils.encode_args(wit_query_params)
    local wit_uri = 'https://' .. sts_host .. '?' .. wit_encoded_query_params

    local httpc = http.new()
    local wit_res, wit_err = httpc:request_uri(wit_uri, {
      method = 'GET',
      headers = {
        Accept            = "application/json",
        ["Content-Type"]  = "application/x-www-form-urlencoded; charset=utf-8"
      },
      ssl_verify = false,
    })

    if not wit_res then
      return nil, 'Unable to call AWS to retrieve the web identity token - error [' .. tostring(wit_err) .. ']'
    end
    if wit_res.status ~= 200 then
      return nil, 'Unable to retrieve the web identity token - status [' .. wit_res.status .. '] - reason [' .. wit_res.reason .. ']'
    end
    local json_wit_credentials = json.decode(wit_res.body).AssumeRoleWithWebIdentityResponse.AssumeRoleWithWebIdentityResult.Credentials
    local wit_credentials = {
      access_key    = json_wit_credentials.AccessKeyId,
      secret_key    = json_wit_credentials.SecretAccessKey,
      session_token = json_wit_credentials.SessionToken,
      expiration    = json_wit_credentials.Expiration
    }

    local assume_role_arn = self.config.aws_assume_role_arn
    if not assume_role_arn then
      log.debug('Use web identity token with expiration date :', wit_credentials.expiration)
      return wit_credentials, nil, wit_credentials.expiration - ngx_now()
    end

    -- need to assume the cross account role to call the lambda
    local ar_credentials, ar_err = fetch_assume_role_credentials(sts_host, region, assume_role_arn,
      wit_credentials.access_key, wit_credentials.secret_key, wit_credentials.session_token, role_session_name)

    if ar_err then
      -- unable to assume given role
      return nil, ar_err
    end

    return ar_credentials, nil, ar_credentials.expiration - ngx_now()
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


-- Return the provider for EKS environment with service account defined otherwise return nil
local get_provider = function (config)
  if not (ROLE_ARN and WEB_IDENTITY_TOKEN_FILE) then
    return nil
  end

  log.debug('The web identity token provider is configured')
  return create_web_identity_provider(config)
end


return {
  get_provider = get_provider
}
