local schema_def = require "kong.plugins.aws-lambda.schema"
local v = require("spec.helpers").validate_plugin_config_schema


describe("Plugin: AWS Lambda (schema)", function()
  it("accepts nil Unhandled Response Status Code", function()
    local ok, err = v({
      unhandled_status = nil,
      aws_region = "us-east-1",
      function_name = "my-function"
    }, schema_def)

    assert.is_nil(err)
    assert.truthy(ok)
  end)

  it("accepts correct Unhandled Response Status Code", function()
    local ok, err = v({
      unhandled_status = 412,
      aws_region = "us-east-1",
      function_name = "my-function"
    }, schema_def)

    assert.is_nil(err)
    assert.truthy(ok)
  end)

  it("errors with Unhandled Response Status Code less than 100", function()
    local ok, err = v({
      unhandled_status = 99,
      aws_region = "us-east-1",
      function_name = "my-function"
    }, schema_def)

    assert.equal("value should be between 100 and 999", err.config.unhandled_status)
    assert.falsy(ok)
  end)

  it("errors with Unhandled Response Status Code greater than 999", function()
    local ok, err = v({
      unhandled_status = 1000,
      aws_region = "us-east-1",
      function_name = "my-function"
    }, schema_def)

    assert.equal("value should be between 100 and 999", err.config.unhandled_status)
    assert.falsy(ok)
  end)

  it("accepts with neither aws_key nor aws_secret", function()
    local ok, err = v({
      aws_region = "us-east-1",
      function_name = "my-function"
    }, schema_def)

    assert.is_nil(err)
    assert.truthy(ok)
  end)

  it("errors with aws_secret but without aws_key", function()
    local ok, err = v({
      aws_secret = "xx",
      aws_region = "us-east-1",
      function_name = "my-function"
    }, schema_def)

    assert.equal("All or none of 'config.aws_key', 'config.aws_secret' must be set. Only 'config.aws_secret' found", err["@entity"][1])
    assert.falsy(ok)
  end)

  it("errors without aws_secret but with aws_key", function()
    local ok, err = v({
      aws_key = "xx",
      aws_region = "us-east-1",
      function_name = "my-function"
    }, schema_def)

    assert.equal("All or none of 'config.aws_key', 'config.aws_secret' must be set. Only 'config.aws_key' found", err["@entity"][1])
    assert.falsy(ok)
  end)

  it("errors if proxy_scheme is missing while proxy_url is provided", function()
    local ok, err = v({
      proxy_url = "http://hello.com/proxy",
      aws_region = "us-east-1",
      function_name = "my-function"
    }, schema_def)

    assert.equal("All or none of 'config.proxy_scheme', 'config.proxy_url' must be set. Only 'config.proxy_url' found", err["@entity"][1])
    assert.falsy(ok)
  end)

end)
