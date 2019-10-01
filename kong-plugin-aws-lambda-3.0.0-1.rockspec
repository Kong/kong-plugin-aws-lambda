package = "kong-plugin-aws-lambda"
version = "3.0.0-1"

supported_platforms = {"linux", "macosx"}
source = {
  url = "http://github.com/Kong/kong-plugin-aws-lambda.git",
  tag = "3.0.0"
}

description = {
  summary = "Kong plugin to invoke AWS Lambda functions",
  homepage = "http://konghq.com",
  license = "Apache 2.0"
}

dependencies = {
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.aws-lambda.aws-serializer"]       = "kong/plugins/aws-lambda/aws-serializer.lua",
    ["kong.plugins.aws-lambda.handler"]              = "kong/plugins/aws-lambda/handler.lua",
    ["kong.plugins.aws-lambda.iam-ec2-credentials"]  = "kong/plugins/aws-lambda/iam-ec2-credentials.lua",
    ["kong.plugins.aws-lambda.iam-ecs-credentials"]  = "kong/plugins/aws-lambda/iam-ecs-credentials.lua",
    ["kong.plugins.aws-lambda.schema"]               = "kong/plugins/aws-lambda/schema.lua",
    ["kong.plugins.aws-lambda.v4"]                   = "kong/plugins/aws-lambda/v4.lua",
  }
}
