require "spec.helpers"

describe("[AWS Lambda] iam-ecs", function()
  local match = require("luassert.match")

  local env_vars
  local old_getenv = os.getenv

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

  before_each(function()
    package.loaded["kong.plugins.aws-lambda.iam-ecs-credentials"] = nil
    mock_ngx()
    -- mock os.getenv
    os.getenv = function(name)  -- luacheck: ignore
      return (env_vars or {})[name] or old_getenv(name)
    end
  end)

  after_each(function()
    os.getenv = old_getenv  -- luacheck: ignore
  end)

  it("should not instantiate provider when not in ECS environment", function()
    -- GIVEN
    local connect_spy, request_spy = mock_http()
    env_vars = {
      AWS_CONTAINER_CREDENTIALS_RELATIVE_URI = nil,
      ENV_FULL_URI = nil
    }
    local ecs_credentials_provider = require("kong.plugins.aws-lambda.iam-ecs-credentials")

    -- WHEN
    local ecs_credentials_provider_instance = ecs_credentials_provider.get_provider()

    -- THEN
    assert.is_nil(ecs_credentials_provider_instance)
    assert.spy(connect_spy).was.called(0)
    assert.spy(request_spy).was.called(0)
  end)

  it("should fetch credentials from metadata service", function()
    -- GIVEN
    env_vars = {
      ENV_RELATIVE_URI = '/relative/url',
      AWS_CONTAINER_CREDENTIALS_RELATIVE_URI = "/just/a/path"
    }
    local json_response = [[
    {
      "Code":"Success",
      "LastUpdated":"2019-03-12T14:20:45Z",
      "Type":"AWS-HMAC",
      "AccessKeyId":"the Access Key",
      "SecretAccessKey":"the Big Secret",
      "Token":"the Token of Appreciation",
      "Expiration":"2019-03-12T20:56:10Z"
    }
    ]]
    mock_ngx(1552423170) -- equal to json_response.Expiration (2019-03-12T20:56:10Z) minus 1000
    local connect_spy, request_spy = mock_http(true, json_response)
    local ecs_credentials_provider = require("kong.plugins.aws-lambda.iam-ecs-credentials")
    local ecs_credentials_provider_instance = ecs_credentials_provider.get_provider();

    -- WHEN
    local iam_role_credentials, err, duration = ecs_credentials_provider_instance.fetch_credentials()

    -- THEN
    assert.is_nil(err)
    assert.spy(connect_spy).was_called_with(match._, "169.254.170.2", 80)
    assert.spy(request_spy).was.called_with(match._, match.is_same({ method = "GET", path   = "/just/a/path" }))
    assert.spy(connect_spy).was.called(1)
    assert.spy(request_spy).was.called(1)
    assert.equal("the Access Key", iam_role_credentials.access_key)
    assert.equal("the Big Secret", iam_role_credentials.secret_key)
    assert.equal("the Token of Appreciation", iam_role_credentials.session_token)
    assert.equal(1552424170, iam_role_credentials.expiration)
    assert.equal(1000, duration)
  end)
end)
