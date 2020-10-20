-- This code is reverse engineered from the original AWS sdk. Specifically:
-- https://github.com/aws/aws-sdk-js/blob/c175cb2b89576f01c08ebf39b232584e4fa2c0e0/lib/credentials/remote_credentials.js


local function makeset(t)
  for i = 1, #t do
    t[t[i]] = true
  end
  return t
end

local log = kong.log
local ENV_RELATIVE_URI = os.getenv 'AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'
local ENV_FULL_URI = os.getenv 'AWS_CONTAINER_CREDENTIALS_FULL_URI'
local FULL_URI_UNRESTRICTED_PROTOCOLS = makeset { "https" }
local FULL_URI_ALLOWED_PROTOCOLS = makeset { "http", "https" }
local FULL_URI_ALLOWED_HOSTNAMES = makeset { "localhost", "127.0.0.1" }
local RELATIVE_URI_HOST = '169.254.170.2'
local DEFAULT_SERVICE_REQUEST_TIMEOUT = 5000

local url = require "socket.url"
local http = require "resty.http"
local json = require "cjson"
local parse_date = require "luatz".parse.rfc_3339
local ngx_now = ngx.now



-- construct the URL
local function get_ECS_uri()
  if not (ENV_RELATIVE_URI or ENV_FULL_URI) then
    -- No variables found, so we're not running on ECS containers
    log.debug("No ECS environment variables found for IAM")
    return nil
  end

  if ENV_RELATIVE_URI then
    return url.parse('http://' .. RELATIVE_URI_HOST .. ENV_RELATIVE_URI)
  end

  if ENV_FULL_URI then
    local parsed_url = url.parse(ENV_FULL_URI)

    if not FULL_URI_ALLOWED_PROTOCOLS[parsed_url.scheme] then
      local errMessage = 'Unsupported protocol: AWS.RemoteCredentials supports '
             .. table.concat(FULL_URI_ALLOWED_PROTOCOLS, ',') .. ' only; '
             .. parsed_url.scheme .. ' requested.'
      log.err("Failed to construct ECS IAM url: ", errMessage)
      return nil
    end

    if (not FULL_URI_UNRESTRICTED_PROTOCOLS[parsed_url.scheme]) and
       (not FULL_URI_ALLOWED_HOSTNAMES[parsed_url.hostname]) then
      local errMessage = 'Unsupported hostname: AWS.RemoteCredentials only supports '
                .. table.concat(FULL_URI_ALLOWED_HOSTNAMES, ',') .. ' for '
                .. parsed_url.scheme .. '; ' .. parsed_url.scheme .. '://'
                .. parsed_url.host .. ' requested.'
      log.err("Failed to construct ECS IAM url: ", errMessage)
      return nil
    end

    return parsed_url
  end

  log.err("Failed to construct ECS IAM url: ", 'Environment variable AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or '
         .. 'AWS_CONTAINER_CREDENTIALS_FULL_URI must be set to use AWS.RemoteCredentials.')
  return nil
end

local function get_ECS_full_uri()
  local ECS_full_uri = get_ECS_uri()
  if ECS_full_uri then
    -- set a default port if omitted
    ECS_full_uri.port = ECS_full_uri.port or ({ http = 80, https = 443 })[ECS_full_uri.scheme]
    return ECS_full_uri
  end

  return nil
end


local function create_ecs_provider(ECS_full_uri)
  local self = { ECS_full_uri = ECS_full_uri}

  local function fetch_credentials()
    local client = http.new()
    client:set_timeout(DEFAULT_SERVICE_REQUEST_TIMEOUT)

    local ok, err = client:connect(self.ECS_full_uri.host, self.ECS_full_uri.port)

    if not ok then
      return nil, "Could not connect to metadata service: " .. tostring(err)
    end

    local response, err = client:request {
      method = "GET",
      path   = self.ECS_full_uri.path,
    }

    if not response then
      return nil, "Failed to request IAM credentials request returned error: " .. tostring(err)
    end

    if response.status ~= 200 then
      return nil, "Unable to request IAM credentials request returned status code " ..
                  response.status .. " " .. tostring(response:read_body())
    end

    local credentials = json.decode(response:read_body())

    log.debug("Received temporary IAM credential from ECS metadata " ..
                        "service with session token: ", credentials.Token)

    local result = {
      access_key    = credentials.AccessKeyId,
      secret_key    = credentials.SecretAccessKey,
      session_token = credentials.Token,
      expiration    = parse_date(credentials.Expiration):timestamp()
    }
    return result, nil, result.expiration - ngx_now()
  end

  --
  -- PUBLIC FUNCTIONS
  --
  local fetch_credentials_logged = function()
    -- wrapper to log any errors
    local creds, err, ttl = fetch_credentials(self.ECS_full_uri)
    if creds then
      return creds, err, ttl
    end
    log.err(err)
  end

  return {
    fetch_credentials = fetch_credentials_logged,
  }

end

-- Get the ECS provider if it's configured
local get_provider = function ()
  local ECS_full_uri = get_ECS_full_uri()
  if not ECS_full_uri then
    return nil
  end

  return create_ecs_provider(ECS_full_uri)
end


return {
  get_provider = get_provider
}
