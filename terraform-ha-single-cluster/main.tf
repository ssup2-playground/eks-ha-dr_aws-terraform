## Provider
provider "aws" {
  region = local.region
}

provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

provider "helm" {
  # https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

## Data
data "aws_availability_zones" "available" {}

## Local Vars
locals {
  name   = "eks-ha-single-cluster"
  region = "us-east-2"

  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
}

## VPC
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"

  name = local.name
  cidr = local.vpc_cidr

  azs              = local.azs
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 10)]
  database_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 4, k + 10)]

  enable_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  manage_default_network_acl    = true
  manage_default_route_table    = true
  manage_default_security_group = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
}

## EFS
module "efs" {
  source = "terraform-aws-modules/efs/aws"

  name = local.name

  mount_targets = { for k, v in zipmap(local.azs, module.vpc.private_subnets) : k => { subnet_id = v } }

  security_group_vpc_id = module.vpc.vpc_id
  security_group_rules  = {
    vpc = {
      cidr_blocks = module.vpc.private_subnets_cidr_blocks
    }
  }
}

## Aurora
module "aurora_mysql" {
  source  = "terraform-aws-modules/rds-aurora/aws"

  name = local.name
  engine = "aurora-mysql"

  instance_class = "db.r5.large"
  instances = { 
    one = {}
    two = {}
  }

  vpc_id                 = module.vpc.vpc_id
  create_security_group  = true
  allowed_cidr_blocks    = module.vpc.private_subnets_cidr_blocks
  create_db_subnet_group = false
  db_subnet_group_name   = module.vpc.database_subnet_group_name

  create_random_password = false
  master_password = "adminadmin"
}

## EKS
module "eks" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name                   = local.name
  cluster_endpoint_public_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  eks_managed_node_groups = {
    control = {
      min_size     = 2
      max_size     = 2
      desired_size = 2

      instance_types = ["t3.large"]
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }

      labels = {
        type = "control"
      }
    }

    service = {
      min_size     = 6
      max_size     = 12
      desired_size = 6

      instance_types = ["t3.large"]
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }

      labels = {
        type = "service"
      }
    }
  }
}

## EKS / Cluster Autoscaler
module "eks_cluster_autoscaler_irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                        = format("%s-%s", "cluster-autoscaler", local.name)
  attach_cluster_autoscaler_policy = true
  cluster_autoscaler_cluster_ids   = [module.eks.cluster_name]

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }
}

resource "kubernetes_service_account" "eks_cluster_autoscaler_service_account" {
  metadata {
    namespace = "kube-system"
    name      = "cluster-autoscaler"

    annotations = {
      "eks.amazonaws.com/role-arn" = module.eks_cluster_autoscaler_irsa_role.iam_role_arn
    }
  }
}

## EKS / Load Balancer Controller
module "eks_load_balancer_controller_irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-%s", "eks-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "kubernetes_service_account" "eks_load_balancer_controller_service_account" {
  metadata {
    namespace = "kube-system"
    name      = "aws-load-balancer-controller"

    annotations = {
      "eks.amazonaws.com/role-arn" = module.eks_load_balancer_controller_irsa_role.iam_role_arn
    }
  }
}

## EKS / External DNS
module "eks_external_dns_irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                  = format("%s-%s", "eks-external-dns", local.name)
  attach_external_dns_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
}

resource "kubernetes_service_account" "eks_external_dns_service_account" {
  metadata {
    namespace = "kube-system"
    name      = "external-dns"

    annotations = {
      "eks.amazonaws.com/role-arn" = module.eks_external_dns_irsa_role.iam_role_arn
    }
  }
}

## EKS / EFS CSI
module "eks_efs_csi_irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-%s", "efs-csi", local.name)
  attach_efs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:efs-csi-controller-sa"]
    }
  }
}

resource "kubernetes_service_account" "eks_efs_csi_service_account" {
  metadata {
    namespace = "kube-system"
    name      = "efs-csi-controller-sa"

    annotations = {
      "eks.amazonaws.com/role-arn" = module.eks_efs_csi_irsa_role.iam_role_arn
    }
  }
}

## EKS / Metric Server
resource "helm_release" "metrics_server" {
  namespace  = "kube-system"
  name       = "metrics-server"
  chart      = "metrics-server"
  repository = "https://kubernetes-sigs.github.io/metrics-server/"
 
  set {
    name  = "replicas"
    value = 2
  } 
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
}
