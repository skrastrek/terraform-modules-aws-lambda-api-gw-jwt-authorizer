resource "aws_iam_role" "this" {
  name               = var.name
  assume_role_policy = module.assume_role_policy_document.json

  tags = var.tags
}

module "assume_role_policy_document" {
  source  = "skrastrek/iam/aws//modules/policy-document/service-assume-role"
  version = "1.4.0"

  service_identifiers = ["lambda.amazonaws.com"]
}

resource "aws_iam_role_policy_attachment" "aws_lambda_basic_execution_role" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}
