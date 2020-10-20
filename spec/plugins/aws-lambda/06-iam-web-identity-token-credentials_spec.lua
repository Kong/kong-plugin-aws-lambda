require "spec.helpers"
local io = require "io"


describe("[AWS Lambda] iam-web-identity-token-credentials", function()

  local old_getenv, old_io_open = os.getenv, io.open
  local match = require("luassert.match")

  local function mock_http(connect_res, request_res)
    local connect_spy = spy.new(function() return connect_res end)
    local request_spy = spy.new(function() return {
        status = 200,
        read_body = function() return request_res end
      } end)

    package.loaded["resty.http"] = nil
    local http = require "resty.http"
    http.new = function() return {
      set_timeout = function() end,
      connect = connect_spy,
      request = request_spy
    } end

    return connect_spy, request_spy
  end

  local function mock_ngx(duration)
    ngx.now = function() return duration end  -- luacheck: ignore
  end

  local function mock_getEnv(variables)
    -- mock os.getenv
    os.getenv = function(name)  -- luacheck: ignore
      return variables[name]--(variables or {})[name] or old_getenv(name)
    end
  end

  local function mock_io(json_Credentials)
    io.open = function()
      return {
        read = function() return json_Credentials end,
        close = function() end
      }
    end
  end

  before_each(function()
    package.loaded["kong.plugins.aws-lambda.iam-web-identity-token-credentials"] = nil
  end)

  after_each(function()
    os.getenv = old_getenv  -- luacheck: ignore
    io.open = old_io_open
  end)


  it("should not fetch web identity token when WEB_IDENTITY_TOKEN_FILE is not defined", function()
    -- GIVEN
    mock_getEnv({ AWS_ROLE_ARN = "arn:aws:iam:111111111111:role/RoleNameToAssume" })

    -- WHEN
    local web_identity_token_provider = require("kong.plugins.aws-lambda.iam-web-identity-token-credentials")
    local web_identity_token_provider_instance = web_identity_token_provider.get_provider()

    -- THEN
    assert.is_nil(web_identity_token_provider_instance)
  end)


  it("should not fetch web identity token when ROLE_ARN is not defined", function()
    -- GIVEN
    mock_getEnv({ AWS_WEB_IDENTITY_TOKEN_FILE = "/path/to/a/token" })

    -- WHEN
    local web_identity_token_provider = require("kong.plugins.aws-lambda.iam-web-identity-token-credentials")
    local web_identity_token_provider_instance = web_identity_token_provider.get_provider()

    -- THEN
    assert.is_nil(web_identity_token_provider_instance)
  end)


  it("should fetch credentials with region from web identity token service", function()
    -- GIVEN
    local env_vars = {
      AWS_WEB_IDENTITY_TOKEN_FILE = "/path/to/a/token",
      AWS_ROLE_ARN = "arn:aws:iam:111111111111:role/RoleNameToAssume"
    }
    mock_getEnv(env_vars)
    local config = {
      aws_region = "eu-west-1",
      aws_role_session_name = "arn:aws:iam:222222222222:role/OverrideRole"
    }
    -- token store un the file AWS_WEB_IDENTITY_TOKEN_FILE
    local web_identity_token = "y87oGKPznh0D6bEQZTSCzyoCtL_8S07pLpr0"
    mock_io(web_identity_token)

    local sts_response = [[
    {
      "AssumedRoleUser": {
        "AssumedRoleId": "EAZDC3:kong-role",
        "Arn": "arn:aws:sts::123456789012:assumed-role/blv-kong-trust-role"
      },
      "Audience": "sts.amazonaws.com",
      "Provider": "arn:aws:iam::123456789012:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/ZDJ32JRD",
      "SubjectFromWebIdentityToken": "system:serviceaccount:namespace:serviceAccountName",
      "Credentials": {
        "SecretAccessKey": "Secret_Key",
        "SessionToken": "Aws_Session_Token",
        "Expiration": "2020-10-16T14:50:57Z",
        "AccessKeyId": "Access_Key_Id"
      }
    }
    ]]

    local connect_spy, request_spy = mock_http(true, sts_response)
    mock_ngx(1602859757) -- equals to Credentials.Expiration (2020-10-16T14:50:57Z) minus 100

    local web_identity_token_provider = require("kong.plugins.aws-lambda.iam-web-identity-token-credentials")
    local web_identity_token_provider_instance = web_identity_token_provider.get_provider(config)
    local expected_query_params = {
      {
        Action           = "AssumeRoleWithWebIdentity",
        Version          = "2011-06-15",
        RoleArn          = env_vars.AWS_ROLE_ARN,
        DurationSeconds  = "3600",
        ExternalId       = "kong-plugin-lambda",
        WebIdentityToken = web_identity_token,
        RoleSessionName  = config.aws_role_session_name
      },
      headers = {
        Accept = "application/json"
      },
      method = "GET",
      path = "/"
    }

    -- WHEN
    local iam_role_credentials, err, duration = web_identity_token_provider_instance.fetch_credentials()

    -- THEN
    assert.is_nil(err)
    assert.spy(connect_spy).was.called(1)
    assert.spy(connect_spy).was.called_with(match._, "sts.eu-west-1.amazonaws.com", 443)
    assert.spy(request_spy).was.called(1)
    assert.spy(request_spy).was.called_with(match._, match.is_same(expected_query_params))
    assert.equal("Access_Key_Id", iam_role_credentials.access_key)
    assert.equal("Secret_Key", iam_role_credentials.secret_key)
    assert.equal("Aws_Session_Token", iam_role_credentials.session_token)
    assert.equal(iam_role_credentials.expiration, 1602859857)
    assert.equal(100, duration)
  end)
end)
