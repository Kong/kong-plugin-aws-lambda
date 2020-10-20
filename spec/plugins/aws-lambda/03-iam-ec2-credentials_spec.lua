require "spec.helpers"

describe("[AWS Lambda] iam-ec2", function()

  local http_responses
  local ec2_provider

  before_each(function()
    package.loaded["kong.plugins.aws-lambda.iam-ec2-credentials"] = nil
    package.loaded["resty.http"] = nil
    ec2_provider = require("kong.plugins.aws-lambda.iam-ec2-credentials")
    -- mock the http module
    local http = require "resty.http"
    http.new = function()
      return {
        set_timeout = function() end,
        connect = function()
          return true
        end,
        request = function()
          return {
            status = 200,
            read_body = function()
              local body = http_responses[1]
              table.remove(http_responses, 1)
              return body
            end,
          }
        end,
      }
    end
  end)

  after_each(function()
  end)

  it("should fetch credentials from metadata service", function()
    -- GIVEN
    http_responses = {
      "EC2_role",
      [[
{
  "Code" : "Success",
  "LastUpdated" : "2019-03-12T14:20:45Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "the Access Key",
  "SecretAccessKey" : "the Big Secret",
  "Token" : "the Token of Appreciation",
  "Expiration" : "2019-03-12T20:56:10Z"
}
]]
    }

    local ec2_provider_instance = ec2_provider.get_provider()

    -- WHEN
    local iam_role_credentials, err = ec2_provider_instance.fetch_credentials()

    -- THEN
    assert.is_nil(err)
    assert.equal("the Access Key", iam_role_credentials.access_key)
    assert.equal("the Big Secret", iam_role_credentials.secret_key)
    assert.equal("the Token of Appreciation", iam_role_credentials.session_token)
    assert.equal(1552424170, iam_role_credentials.expiration)
  end)
end)

