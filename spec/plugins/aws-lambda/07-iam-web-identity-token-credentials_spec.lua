require "spec.helpers"
local io = require "io"

describe("[AWS Lambda] iam-web-identity-token-credentials", function()

  local old_getenv, old_io_open = os.getenv, io.open
  local nb_request_uri_call

  -- MOCK FUNCTIONS
  local function mock_http(request_results)
    local requests_params = {}
    local request_uri_mock = function(_, uri_param, options_param)
      nb_request_uri_call = nb_request_uri_call + 1
      table.insert(requests_params, { uri_param, options_param })
      return {
        status = 200,
        body = request_results[nb_request_uri_call]
      }
    end

    package.loaded["resty.http"] = nil
    local http = require "resty.http"
    http.new = function() return {
      set_timeout = function() end,
      request_uri = request_uri_mock,
      close = function() end
    } end

    return requests_params
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
    return static_sign1 == static_sign2
  end

  before_each(function()
    nb_request_uri_call = 0
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


  it("should fetch credentials without region from web identity token service", function()
    -- GIVEN
    local env_vars = {
      AWS_WEB_IDENTITY_TOKEN_FILE = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
      AWS_ROLE_ARN = "arn:aws:iam:111111111111:role/role-associate-to-service-account"
    }
    mock_getEnv(env_vars)
    local config = { }

    -- token store in the the file AWS_WEB_IDENTITY_TOKEN_FILE
    local web_identity_token = "secret_token_stored_in_file"
    mock_io(web_identity_token)

    local wit_from_sts_response = [[
      {
        "AssumeRoleWithWebIdentityResponse": {
          "AssumeRoleWithWebIdentityResult": {
            "AssumedRoleUser": {
              "Arn": "arn:aws:sts::111111111111:assumed-role/role-associate-to-service-account",
              "AssumedRoleId": "AROACLKWSDQRAOEXAMPLE:TestAR"
            },
            "Audience": "sts.amazonaws.com",
            "Credentials": {
              "AccessKeyId": "ASgeIAIOSFODNN7EXAMPLE",
              "Expiration": 1603577714,
              "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
              "SessionToken": "AQoDYXdzEE0a8ANXXXXXXXXNO1ewxE5TijQyp+IEXAMPLE"
            },
            "PackedPolicySize": null,
            "Provider": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/EAZCZAERACAZE",
            "SubjectFromWebIdentityToken": "amzn1.account.AF6RHO7KZU5XRVQJGXK6HB56KR2A"
          },
          "ResponseMetadata": {
            "RequestId": "ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE"
          }
        }
      }
    ]]


    local requests_params = mock_http({ wit_from_sts_response })
    mock_ngx(1603577614) -- equals to Credentials.Expiration (2020-10-16T14:50:57Z) minus 100

    local expected_wit_uri = 'https://sts.amazonaws.com?Action=AssumeRoleWithWebIdentity&DurationSeconds=3600&RoleArn=arn%3aaws%3aiam%3a111111111111%3arole%2frole%2dassociate%2dto%2dservice%2daccount&RoleSessionName=kong%2dplugin%2dlambda&Version=2011%2d06%2d15&WebIdentityToken=secret_token_stored_in_file'
    local expected_options = {
      headers = {
        Accept = "application/json",
        ["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
      },
      method = "GET",
      ssl_verify = false
    }

    local web_identity_token_provider = require("kong.plugins.aws-lambda.iam-web-identity-token-credentials")
    local web_identity_token_provider_instance = web_identity_token_provider.get_provider(config)

    -- WHEN
    local iam_role_credentials, err, duration = web_identity_token_provider_instance.fetch_credentials()

    -- THEN
    assert.is_nil(err)
    assert.equal(table.getn(requests_params), 1) -- luacheck: ignore
    local wit_uri = requests_params[1][1]
    local wit_query_params = requests_params[1][2]
    assert.equal(expected_wit_uri,                                  wit_uri)
    assert.same(wit_query_params,                                   expected_options)
    assert.equal("ASgeIAIOSFODNN7EXAMPLE",                          iam_role_credentials.access_key)
    assert.equal("wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",       iam_role_credentials.secret_key)
    assert.equal("AQoDYXdzEE0a8ANXXXXXXXXNO1ewxE5TijQyp+IEXAMPLE",  iam_role_credentials.session_token)
    assert.equal(iam_role_credentials.expiration,                   1603577714)
    assert.equal(100,                                               duration)
  end)


  it("should fetch credentials with region from web identity token service and assume role", function()
    -- GIVEN
    local env_vars = {
      AWS_WEB_IDENTITY_TOKEN_FILE = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
      AWS_ROLE_ARN = "arn:aws:iam:111111111111:role/role-associate-to-service-account"
    }
    mock_getEnv(env_vars)
    local config = {
      aws_region = "eu-west-1",
      aws_role_session_name = "role-session-name",
      aws_assume_role_arn = "role-to-assume"
    }

    -- token store in the the file AWS_WEB_IDENTITY_TOKEN_FILE
    local web_identity_token = "secret_token_stored_in_file"
    mock_io(web_identity_token)

    local wit_from_sts_response = [[
      {
        "AssumeRoleWithWebIdentityResponse": {
          "AssumeRoleWithWebIdentityResult": {
            "AssumedRoleUser": {
              "Arn": "arn:aws:sts::111111111111:assumed-role/role-associate-to-service-account",
              "AssumedRoleId": "AROACLKWSDQRAOEXAMPLE:TestAR"
            },
            "Audience": "sts.amazonaws.com",
            "Credentials": {
              "AccessKeyId": "ASgeIAIOSFODNN7EXAMPLE",
              "Expiration": 1603577714,
              "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
              "SessionToken": "AQoDYXdzEE0a8ANXXXXXXXXNO1ewxE5TijQyp+IEXAMPLE"
            },
            "PackedPolicySize": null,
            "Provider": "arn:aws:iam::111111111111:oidc-provider/oidc.eks.eu-west-1.amazonaws.com/id/EAZCZAERACAZE",
            "SubjectFromWebIdentityToken": "amzn1.account.AF6RHO7KZU5XRVQJGXK6HB56KR2A"
          },
          "ResponseMetadata": {
            "RequestId": "ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE"
          }
        }
      }
    ]]
    local assume_role_response = [[
    {
      "AssumeRoleResponse": {
        "AssumeRoleResult": {
          "AssumedRoleUser": {
            "Arn": "arn:aws:sts::668763965404:assumed-role/role-to-assume/TestAR",
            "AssumedRoleId": "ARO123EXAMPLE123:TestAR"
          },
          "Credentials": {
            "AccessKeyId": "AR-ASIAIOSFODNN7EXAMPLE",
            "Expiration": 1603573015,
            "SecretAccessKey": "AR-JalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",
            "SessionToken": "AR-AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWBA=="
          },
          "PackedPolicySize": null
        },
        "ResponseMetadata": {
          "RequestId": "c6104cbe-af31-11e0-8154-cbc7ccf896c7"
        }
      }
    }
    ]]


    local captured_requests_params = mock_http({ wit_from_sts_response, assume_role_response })
    mock_ngx(1603573005) -- equals to Credentials.Expiration (2020-10-16T14:50:57Z) minus 10

    local expected_wit_uri = 'https://sts.eu-west-1.amazonaws.com?Action=AssumeRoleWithWebIdentity&DurationSeconds=3600&RoleArn=arn%3aaws%3aiam%3a111111111111%3arole%2frole%2dassociate%2dto%2dservice%2daccount&RoleSessionName=role%2dsession%2dname&Version=2011%2d06%2d15&WebIdentityToken=secret_token_stored_in_file'
    local expected_wit_options = {
      headers = {
        Accept = "application/json",
        ["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8"
      },
      method = "GET",
      ssl_verify = false
    }
    local expected_ar_uri = 'https://sts.eu-west-1.amazonaws.com/?Action=AssumeRole&DurationSeconds=3600&RoleArn=role%2dto%2dassume&RoleSessionName=role%2dsession%2dname&Version=2011%2d06%2d15'
    local expected_ar_options = {
      headers = {
        Accept = 'application/json',
        Authorization = 'AWS4-HMAC-SHA256 Credential=ASgeIAIOSFODNN7EXAMPLE/20201024/eu-west-1/sts/aws4_request, SignedHeaders=accept;content-type;host;x-amz-date;x-amz-security-token, Signature=ba314f031b1ff28954d8dffe58dca17cb57f412ba522bc87bbee732ddd8e1aad',
        ["Content-Type"] = 'application/x-www-form-urlencoded; charset=utf-8',
        Host = 'sts.eu-west-1.amazonaws.com',
        ["X-Amz-Date"] = '20201024T220547Z',
        ["X-Amz-Security-Token"] = 'AQoDYXdzEE0a8ANXXXXXXXXNO1ewxE5TijQyp+IEXAMPLE'
      },
      method = 'GET',
      ssl_verify = false
    }

    local web_identity_token_provider = require("kong.plugins.aws-lambda.iam-web-identity-token-credentials")
    local web_identity_token_provider_instance = web_identity_token_provider.get_provider(config)

    -- WHEN
    local iam_role_credentials, err, duration = web_identity_token_provider_instance.fetch_credentials()

    -- THEN
    assert.is_nil(err)
    assert.equal(table.getn(captured_requests_params), 2) -- luacheck: ignore

    local wit_uri = captured_requests_params[1][1]
    local wit_query_params = captured_requests_params[1][2]
    assert.equal(expected_wit_uri, wit_uri)
    assert.same(expected_wit_options, wit_query_params)

    local ar_uri = captured_requests_params[2][1]
    local ar_query_params = captured_requests_params[2][2]
    assert.equal(expected_ar_uri, ar_uri)
    assert.equal(expected_ar_options.method, ar_query_params.method)
    assert.same(expected_ar_options.ssl_verify, ar_query_params.ssl_verify)
    assert.same(expected_ar_options.headers["X-Amz-Security-Token"], ar_query_params.headers["X-Amz-Security-Token"])
    assert.is_true(assert_same_sign(expected_ar_options.headers.Authorization, ar_query_params.headers.Authorization))
    assert.equal("AR-ASIAIOSFODNN7EXAMPLE",                                                     iam_role_credentials.access_key)
    assert.equal("AR-JalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY",                                 iam_role_credentials.secret_key)
    assert.equal("AR-AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWBA==",  iam_role_credentials.session_token)
    assert.equal(iam_role_credentials.expiration,                                               1603573015)
    assert.equal(10,                                                                            duration)

  end)


end)
