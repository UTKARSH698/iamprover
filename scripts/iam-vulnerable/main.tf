terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
# Offline planning: dummy credentials, no AWS API calls for identity.
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "AKIAEXAMPLEEXAMPLE00"
  secret_key                  = "dummy"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}
locals {
  account_id = "111122223333"
  caller_arn = "arn:aws:iam::111122223333:user/benchmark-operator"
}
module "privesc-paths" {
  source              = "./modules/free-resources/privesc-paths"
  aws_assume_role_arn = local.caller_arn
  aws_root_user       = "arn:aws:iam::111122223333:root"
}
module "tool-testing" {
  source              = "./modules/free-resources/tool-testing"
  aws_assume_role_arn = local.caller_arn
  aws_root_user       = "arn:aws:iam::111122223333:root"
}
