require "spec.helpers"
local io = require "io"

describe("[AWS Lambda] iam-web-identity-token-credentials", function()

  local old_getenv, old_io_open = os.getenv, io.open
  local match = require("luassert.match")
  local nb_request_call

  -- MOCK FUNCTIONS
  local function mock_http(connect_result, request_results)
    local all_params = {}
    local connect_spy = spy.new(function() return connect_result end)
    local request_spy = spy.new(function(_, p2)
      table.insert(all_params, p2)
      return {
        status = 200,
        read_body = function()
          nb_request_call = nb_request_call + 1
          return request_results[nb_request_call]
        end
      } end)

    package.loaded["resty.http"] = nil
    local http = require "resty.http"
    http.new = function() return {
      set_timeout = function() end,
      connect = connect_spy,
      request = request_spy,
      close = function() end
    } end

    return connect_spy, request_spy, all_params
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

  local function assert_same_sign(sign1, sign2)
    -- need to remove variable information like date and Signature
    local static_sign1 = sign1:gsub("Signature=.+", ""):gsub("/%d%d%d%d%d%d%d%d/", "")
    local static_sign2 = sign2:gsub("Signature=.+", ""):gsub("/%d%d%d%d%d%d%d%d/", "")
    assert.equals(static_sign1, static_sign2)
  end

  before_each(function()
    nb_request_call = 0
    package.loaded["kong.plugins.aws-lambda.iam-web-identity-token-credentials"] = nil
  end)

  after_each(function()
    os.getenv = old_getenv  -- luacheck: ignore
    io.open = old_io_open
  end)


  it("should not fetch web identity token when WEB_IDENTITY_TOKEN_FILE is not defined", function()
    -- GIVEN
    mock_getEnv({ AWS_ROLE_ARN = "arn:aws:iam:111111111111:role/roleAssociatedToServiceAccount" })

    -- WHEN
    local web_identity_token_provider = require("kong.plugins.aws-lambda.iam-web-identity-token-credentials")
    local web_identity_token_provider_instance = web_identity_token_provider.get_provider()

    -- THEN
    assert.is_nil(web_identity_token_provider_instance)
  end)


  it("should not fetch web identity token when ROLE_ARN is not defined", function()
    -- GIVEN
    mock_getEnv({ AWS_WEB_IDENTITY_TOKEN_FILE = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token" })

    -- WHEN
    local web_identity_token_provider = require("kong.plugins.aws-lambda.iam-web-identity-token-credentials")
    local web_identity_token_provider_instance = web_identity_token_provider.get_provider()

    -- THEN
    assert.is_nil(web_identity_token_provider_instance)
  end)


  it("should fetch credentials with region from web identity token service", function()
    -- GIVEN
    local env_vars = {
      AWS_WEB_IDENTITY_TOKEN_FILE = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
      AWS_ROLE_ARN = "arn:aws:iam:111111111111:role/roleAssociatedToServiceAccount"
    }
    mock_getEnv(env_vars)
    local config = {
      aws_region = "eu-west-1",
      aws_role_session_name = "my-custom-session-name"
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

    local connect_spy, request_spy = mock_http(true, { sts_response })
    mock_ngx(1602859757) -- equals to Credentials.Expiration (2020-10-16T14:50:57Z) minus 100

    local web_identity_token_provider = require("kong.plugins.aws-lambda.iam-web-identity-token-credentials")
    local web_identity_token_provider_instance = web_identity_token_provider.get_provider(config)
    local expected_query_params = {
      {
        Action           = "AssumeRoleWithWebIdentity",
        Version          = "2011-06-15",
        RoleArn          = env_vars.AWS_ROLE_ARN,
        DurationSeconds  = 3600,
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
    assert.equal("Access_Key_Id",                 iam_role_credentials.access_key)
    assert.equal("Secret_Key",                    iam_role_credentials.secret_key)
    assert.equal("Aws_Session_Token",             iam_role_credentials.session_token)
    assert.equal(iam_role_credentials.expiration, 1602859857)
    assert.equal(100,                             duration)
  end)

  it("should fetch credentials for assume role with region from web identity token service", function()
    -- GIVEN
    local env_vars = {
      AWS_WEB_IDENTITY_TOKEN_FILE = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
      AWS_ROLE_ARN = "arn:aws:iam:111111111111:role/roleAssociatedToServiceAccount"
    }
    mock_getEnv(env_vars)
    local config = {
      aws_region = "eu-west-1",
      aws_role_session_name = "my-custom-session-name",
      aws_cross_account_role = "arn:aws:iam:2222222:role/OtherRoleToAssume"
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
    local assume_role_response = [[
    {
        "AssumedRoleUser": {
            "AssumedRoleId": "AROAZXNLQI:kong-api-gateway",
            "Arn": "arn:aws:sts::22222222222:assumed-role/blv-kong-called-cross/kong-api-gateway"
        },
        "Credentials": {
            "SecretAccessKey": "Secret_Access_Key_Assume_Role",
            "SessionToken": "Session_Token_Assume_Role",
            "Expiration": "2020-10-21T13:41:41Z",
            "AccessKeyId": "Access_Key_Assume_Role_Id"
        }
    }
    ]]

    local connect_spy, request_spy, request_params = mock_http(true, { sts_response, assume_role_response })
    mock_ngx(1603277701) -- equals to Credentials.Expiration (2020-10-16T14:50:57Z) minus 100

    local web_identity_token_provider = require("kong.plugins.aws-lambda.iam-web-identity-token-credentials")
    local web_identity_token_provider_instance = web_identity_token_provider.get_provider(config)
    local expected_query_params_to_sts = {
      {
        Action           = "AssumeRoleWithWebIdentity",
        Version          = "2011-06-15",
        RoleArn          = env_vars.AWS_ROLE_ARN,
        DurationSeconds  = 3600,
        WebIdentityToken = web_identity_token,
        RoleSessionName  = config.aws_role_session_name
      },
      headers = {
        Accept = "application/json"
      },
      method = "GET",
      path = "/"
    }
    local expected_query_params_to_assume_role = {
      headers = {
        Accept = "application/json",
        Authorization = "AWS4-HMAC-SHA256 Credential=Access_Key_Id/20201021/eu-west-1/sts/aws4_request, SignedHeaders=accept;content-type;host;x-amz-date;x-amz-security-token, Signature=ebae364791578ff30cb559117a31eb6ab9d74264cea9b9a1ae4fe3288f6b2911",
        ["Content-Type"] = "application/json",
        Host = "sts.eu-west-1.amazonaws.com",
        ["X-Amz-Date"] = "20201021T183132Z"
      },
      method = "POST",
      path = "https://sts.eu-west-1.amazonaws.com/?Version=2011%2d06%2d15&RoleArn=arn%3aaws%3aiam%3a2222222%3arole%2fOtherRoleToAssume&DurationSeconds=3600&RoleSessionName=my%2dcustom%2dsession%2dname&Action=AssumeRole"
    }

    -- WHEN
    local iam_role_credentials, err, duration = web_identity_token_provider_instance.fetch_credentials()

    -- THEN
    assert.is_nil(err)

    assert.spy(connect_spy).was.called(1)
    assert.spy(connect_spy).was.called_with(match._, "sts.eu-west-1.amazonaws.com", 443)

    assert.spy(request_spy).was.called(2)

    -- check call assumeRoleWithWebIdentity
    local param_request_assume_role_with_wi = request_params[1]
    assert.equal(expected_query_params_to_sts.Action,           param_request_assume_role_with_wi.Action)
    assert.equal(expected_query_params_to_sts.Version,          param_request_assume_role_with_wi.Version)
    assert.equal(expected_query_params_to_sts.RoleArn,          param_request_assume_role_with_wi.RoleArn)
    assert.equal(expected_query_params_to_sts.DurationSeconds,  param_request_assume_role_with_wi.DurationSeconds)
    assert.equal(expected_query_params_to_sts.WebIdentityToken, param_request_assume_role_with_wi.WebIdentityToken)
    assert.equal(expected_query_params_to_sts.RoleSessionName,  param_request_assume_role_with_wi.RoleSessionName)

    -- check call assumeRole
    local param_request_assume_role = request_params[2]
    assert.equal(expected_query_params_to_assume_role.headers.Accept,                     param_request_assume_role.headers.Accept)
    assert_same_sign(expected_query_params_to_assume_role.headers.Authorization,  param_request_assume_role.headers.Authorization)
    assert.equal(expected_query_params_to_assume_role.headers.Host,                       param_request_assume_role.headers.Host)
    assert.equal(expected_query_params_to_assume_role.method,                             param_request_assume_role.method)
    assert.equal(expected_query_params_to_assume_role.path,                               param_request_assume_role.path)

    -- check return
    assert.equal("Access_Key_Assume_Role_Id",     iam_role_credentials.access_key)
    assert.equal("Secret_Access_Key_Assume_Role", iam_role_credentials.secret_key)
    assert.equal("Session_Token_Assume_Role",     iam_role_credentials.session_token)
    assert.equal(1603287701,                      iam_role_credentials.expiration)
    assert.equal(10000,                           duration)
  end)

end)
