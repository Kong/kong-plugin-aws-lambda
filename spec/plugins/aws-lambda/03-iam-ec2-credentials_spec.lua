require "spec.helpers"

describe("[AWS Lambda] iam-ec2", function()

  local fetch_ec2, fetch_region, http_responses

  before_each(function()
    package.loaded["kong.plugins.aws-lambda.iam-ec2-credentials"] = nil
    package.loaded["resty.http"] = nil
    local http = require "resty.http"
    -- mock the http module
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
    fetch_ec2 = require("kong.plugins.aws-lambda.iam-ec2-credentials").fetchCredentials
    fetch_region = require("kong.plugins.aws-lambda.iam-ec2-credentials").fetchRegion
  end)

  after_each(function()
  end)

  it("should fetch credentials from metadata service", function()
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

    local iam_role_credentials, err = fetch_ec2()

    assert.is_nil(err)
    assert.equal("the Access Key", iam_role_credentials.access_key)
    assert.equal("the Big Secret", iam_role_credentials.secret_key)
    assert.equal("the Token of Appreciation", iam_role_credentials.session_token)
    assert.equal(1552424170, iam_role_credentials.expiration)
  end)
  it("should fetch region metadata service", function()
    http_responses = {
      [[
{
  "accountId" : "832462046160",
  "architecture" : "x86_64",
  "availabilityZone" : "eu-west-3b",
  "billingProducts" : null,
  "devpayProductCodes" : null,
  "marketplaceProductCodes" : null,
  "imageId" : "ami-01b209ce2c9441231",
  "instanceId" : "i-04c6019ed0f4e7ca7",
  "instanceType" : "m5d.2xlarge",
  "kernelId" : null,
  "pendingTime" : "2021-04-29T09:53:04Z",
  "privateIp" : "10.196.93.32",
  "ramdiskId" : null,
  "region" : "eu-west-3",
  "version" : "2017-09-30"
}
]]
    }

    local region, err = fetch_region()

    assert.is_nil(err)
    assert.equal("eu-west-3", region)
  end)
end)
