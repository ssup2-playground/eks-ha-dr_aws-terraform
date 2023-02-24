## Provider
provider "aws" {
  region = local.region
}

## Data
data "aws_availability_zones" "available" {}

## Local Vars
locals {
  name = "eks-ha-dr-desktop"

  region   = "us-west-2"
}

## Desktop Instance
resource "aws_security_group" "rdp_sg" {
  name   = format("%s-rdp", local.name)

  ingress {
    from_port        = 3389
    to_port          = 3389
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }
}

module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"

  name = format("%s-mate", local.name)

  ami                    = "ami-081aaface2871d0d0"
  instance_type          = "m5.large"
  vpc_security_group_ids = [aws_security_group.rdp_sg.id]

  create_iam_instance_profile = true
  iam_role_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }
}

