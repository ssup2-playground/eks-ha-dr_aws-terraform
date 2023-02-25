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
  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
    }
  }
}

provider "kubectl" {
  apply_retry_count      = 5
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks.cluster_name]
  }
}

## Data
data "aws_availability_zones" "available" {}

## Local Vars
locals {
  name = "eks-ha-single"

  region   = "ap-northeast-1"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
  vpc_cidr = "10.0.0.0/16"
}

## Zones
module "zones" {
  source = "terraform-aws-modules/route53/aws//modules/zones"

  zones = {
    format("%s.test", local.name) = {
      vpc = [
        {
          vpc_id = module.vpc.vpc_id
        },
      ]
    }
  }
}

## VPC
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = format("%s-vpc", local.name)

  cidr             = local.vpc_cidr
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
    "kubernetes.io/role/elb" = 1 # for AWS Load Balancer Controller
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1                            # for AWS Load Balancer Controller
    "karpenter.sh/discovery"          = format("%s-eks", local.name) # for Karpenter
  }
}

## EFS
module "efs" {
  source = "terraform-aws-modules/efs/aws"

  name = format("%s-efs", local.name)

  mount_targets = { for k, v in zipmap(local.azs, module.vpc.private_subnets) : k => { subnet_id = v } }

  attach_policy         = false
  security_group_vpc_id = module.vpc.vpc_id
  security_group_rules  = {
    vpc = {
      cidr_blocks = module.vpc.private_subnets_cidr_blocks
    }
  }
}

## Aurora
module "aurora_mysql" {
  source = "terraform-aws-modules/rds-aurora/aws"

  name = format("%s-aurora", local.name)

  engine              = "aurora-mysql"
  skip_final_snapshot = true

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
  master_username        = "admin"
  master_password        = "adminadmin"
}

## EKS
module "eks" {
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-eks", local.name)

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_public_access = true

  eks_managed_node_groups = {
    control = {
      min_size     = 2
      max_size     = 2
      desired_size = 2

      instance_types = ["m5.large"]
      iam_role_additional_policies = {
        AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      }

      labels = {
        type = "control"
      }
    }
  }

  ## Node Security Group
  node_security_group_tags = {
    "karpenter.sh/discovery" = format("%s-eks", local.name) # for Karpenter
  }
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
  }

  ## for Karpenter
  manage_aws_auth_configmap = true
  aws_auth_roles = [
    {
      rolearn  = module.karpenter.role_arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups = [
        "system:bootstrappers",
        "system:nodes",
      ]
    },
  ]
}

## EKS / Karpenter
module "karpenter" {
  source = "terraform-aws-modules/eks/aws//modules/karpenter"

  cluster_name = module.eks.cluster_name

  irsa_oidc_provider_arn       = module.eks.oidc_provider_arn
  iam_role_additional_policies = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
}

resource "helm_release" "karpenter" {
  namespace        = "karpenter"
  create_namespace = true

  name       = "karpenter"
  chart      = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  version    = "v0.24.0"

  set {
    name  = "settings.aws.clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "settings.aws.clusterEndpoint"
    value = module.eks.cluster_endpoint
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.karpenter.irsa_arn
  }
  set {
    name  = "settings.aws.defaultInstanceProfile"
    value = module.karpenter.instance_profile_name
  }
  set {
    name  = "settings.aws.interruptionQueueName"
    value = module.karpenter.queue_name
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
}

resource "kubectl_manifest" "karpenter_provisioner" {
  yaml_body = <<-YAML
    apiVersion: karpenter.sh/v1alpha5
    kind: Provisioner
    metadata:
      name: default
    spec:
      requirements:
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["on-demand"]
        - key: karpenter.k8s.aws/instance-family
          operator: In
          values: ["m5"]
        - key: karpenter.k8s.aws/instance-size
          operator: In
          values: ["large"]
      labels:
        type: service
      limits:
        resources:
          cpu: 1000
          memory: 1000Gi
      providerRef:
        name: default
      ttlSecondsAfterEmpty: 30
  YAML

  depends_on = [
    helm_release.karpenter
  ]
}

resource "kubectl_manifest" "karpenter_node_template" {
  yaml_body = <<-YAML
    apiVersion: karpenter.k8s.aws/v1alpha1
    kind: AWSNodeTemplate
    metadata:
      name: default
    spec:
      subnetSelector:
        karpenter.sh/discovery: ${module.eks.cluster_name}
      securityGroupSelector:
        karpenter.sh/discovery: ${module.eks.cluster_name}
      tags:
        karpenter.sh/discovery: ${module.eks.cluster_name}
  YAML

  depends_on = [
    helm_release.karpenter
  ]
}

## EKS / Load Balancer Controller
module "eks_load_balancer_controller_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("eks-aws-load-balancer-controller-%s", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "aws_load_balancer_controller" {
  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
 
  set {
    name  = "clusterName"
    value = module.eks.cluster_name
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.eks_load_balancer_controller_irsa_role.iam_role_arn
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
}

## EKS / External DNS
module "eks_external_dns_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                  = format("eks-external-dns-%s", local.name)
  attach_external_dns_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
}

resource "helm_release" "external_dns" {
  namespace  = "kube-system"
  name       = "external-dns"
  chart      = "external-dns"
  repository = "https://charts.bitnami.com/bitnami"
 
  set {
    name  = "provider"
    value = "aws"
  }
  set {
    name  = "serviceAccount.name"
    value = "external-dns"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.eks_external_dns_irsa_role.iam_role_arn
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
  set {
    name  = "replicaCount"
    value = 1
  } 
  set {
    name  = "domainFilters[0]"
    value = format("%s.test", local.name) 
  }
}

## EKS / EFS CSI
module "eks_efs_csi_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("eks-efs-csi-%s", local.name)
  attach_efs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:efs-csi-controller-sa"]
    }
  }
}

resource "helm_release" "aws_efs_csi_driver" {
  namespace  = "kube-system"
  name       = "aws-efs-csi-driver"
  chart      = "aws-efs-csi-driver"
  repository = "https://kubernetes-sigs.github.io/aws-efs-csi-driver/"
 
  set {
    name  = "controller.serviceAccount.name"
    value = "efs-csi-controller-sa"
  }
  set {
    name  = "controller.serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.eks_efs_csi_irsa_role.iam_role_arn
  }
  set {
    name  = "controller.nodeSelector.type"
    value = "control"
  }
}

resource "kubectl_manifest" "efs_pv" {
  yaml_body = <<-YAML
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: efs-pv
    spec:
      capacity:
        storage: 5Gi
      volumeMode: Filesystem
      accessModes:
        - ReadWriteMany
      persistentVolumeReclaimPolicy: Retain
      storageClassName: efs-sc
      csi:
        driver: efs.csi.aws.com
        volumeHandle: ${module.efs.id}
  YAML

  depends_on = [
    helm_release.aws_efs_csi_driver
  ]
}

resource "kubectl_manifest" "efs_pvc" {
  yaml_body = <<-YAML
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: efs-pvc
    spec:
      accessModes:
        - ReadWriteMany
      storageClassName: efs-sc
      resources:
        requests:
          storage: 5Gi
  YAML

  depends_on = [
    helm_release.aws_efs_csi_driver
  ]
}

resource "kubectl_manifest" "efs_sc" {
  yaml_body = <<-YAML
    apiVersion: storage.k8s.io/v1
    kind: StorageClass
    metadata:
      name: efs-sc
    provisioner: efs.csi.aws.com
  YAML

  depends_on = [
    helm_release.aws_efs_csi_driver
  ]
}

