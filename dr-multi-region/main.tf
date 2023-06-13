## Provider
provider "aws" {
  alias = "one"

  region = local.one_region
}

provider "aws" {
  alias = "two"

  region = local.two_region
}

provider "kubernetes" {
  alias = "one"

  host                   = module.one_eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.one_eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.one_eks.cluster_name]
  }
}

provider "kubernetes" {
  alias = "two"

  host                   = module.two_eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.two_eks.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.two_eks.cluster_name]
  }
}

provider "helm" {
  alias = "one"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.one_eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.one_eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.one_eks.cluster_name]
    }
  }
}

provider "helm" {
  alias = "two"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.two_eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.two_eks.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.two_eks.cluster_name]
    }
  }
}

provider "kubectl" {
  alias = "one"

  apply_retry_count      = 5
  host                   = module.one_eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.one_eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.one_eks.cluster_name]
  }
}

provider "kubectl" {
  alias = "two"

  apply_retry_count      = 5
  host                   = module.two_eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.two_eks.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.two_eks.cluster_name]
  }
}

## Data
data "aws_availability_zones" "one_available" {
  provider = aws.one
}

data "aws_availability_zones" "two_available" {
  provider = aws.two
}
  
data "aws_caller_identity" "current" {
  provider = aws.one
}

## Local Vars
locals {
  name = "eks-dr-multi"

  one_region = "us-east-1"
  two_region = "us-east-2"
  one_azs    = slice(data.aws_availability_zones.one_available.names, 0, 3)
  two_azs    = slice(data.aws_availability_zones.two_available.names, 0, 3)
  vpc_cidr   = "10.0.0.0/16"
}

## Zones
module "zones" {
  providers = {
    aws = aws.one
  }
  source = "terraform-aws-modules/route53/aws//modules/zones"

  zones = {
    format("%s.test", local.name) = {
      vpc = [
        {
          vpc_id = module.one_vpc.vpc_id
          vpc_region = local.one_region
        },
        {
          vpc_id = module.two_vpc.vpc_id
          vpc_region = local.two_region
        },
      ]
    }
  }
}

## VPC
module "one_vpc" {
  providers = {
    aws = aws.one
  }
  source = "terraform-aws-modules/vpc/aws"

  name = format("%s-one-vpc", local.name)

  cidr             = local.vpc_cidr
  azs              = local.one_azs
  public_subnets   = [for k, v in local.one_azs : cidrsubnet(local.vpc_cidr, 8, k)]
  private_subnets  = [for k, v in local.one_azs : cidrsubnet(local.vpc_cidr, 8, k + 10)]
  database_subnets = [for k, v in local.one_azs : cidrsubnet(local.vpc_cidr, 4, k + 10)]

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

module "two_vpc" {
  providers = {
    aws = aws.two
  }
  source = "terraform-aws-modules/vpc/aws"

  name = format("%s-two-vpc", local.name)

  cidr             = local.vpc_cidr
  azs              = local.two_azs
  public_subnets   = [for k, v in local.two_azs : cidrsubnet(local.vpc_cidr, 8, k)]
  private_subnets  = [for k, v in local.two_azs : cidrsubnet(local.vpc_cidr, 8, k + 10)]
  database_subnets = [for k, v in local.two_azs : cidrsubnet(local.vpc_cidr, 4, k + 10)]

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
resource "aws_efs_file_system" "one_efs" {
  provider = aws.one

  encrypted = true

  tags = {
    Name = format("%s-one-efs", local.name)
  }
}

resource "aws_security_group" "one_efs_sg" {
  provider = aws.one

  name   = format("%s-one-efs-sg", local.name)
  vpc_id = module.one_vpc.vpc_id

  ingress {
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = module.one_vpc.private_subnets_cidr_blocks
  }
}

resource "aws_efs_mount_target" "one_efs_mount_target" {
  provider = aws.one
  
  count           = "${length(module.one_vpc.private_subnets)}"
  subnet_id       = module.one_vpc.private_subnets[count.index]
  file_system_id  = aws_efs_file_system.one_efs.id
  security_groups = [aws_security_group.one_efs_sg.id]
}

resource "aws_efs_replication_configuration" "two_efs" {
  provider = aws.one

  source_file_system_id = aws_efs_file_system.one_efs.id

  destination {
    region = local.two_region
  }
}

resource "aws_security_group" "two_efs_sg" {
  provider = aws.two

  name   = format("%s-two-efs-sg", local.name)
  vpc_id = module.two_vpc.vpc_id

  ingress {
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = module.two_vpc.private_subnets_cidr_blocks
  }
}

resource "aws_efs_mount_target" "two_efs_mount_target" {
  provider = aws.two
  
  count           = "${length(module.two_vpc.private_subnets)}"
  subnet_id       = module.two_vpc.private_subnets[count.index]
  file_system_id  = aws_efs_replication_configuration.two_efs.destination[0].file_system_id
  security_groups = [aws_security_group.two_efs_sg.id]
}

## Aurora
resource "aws_rds_global_cluster" "global_aurora_mysql" {
  provider = aws.one

  global_cluster_identifier = format("%s-global-aurora", local.name)
  engine                    = "aurora-mysql"
  storage_encrypted         = true
}

module "one_aurora_mysql" {
  providers = {
    aws = aws.one
  }
  source = "terraform-aws-modules/rds-aurora/aws"

  name = format("%s-one-aurora", local.name)

  engine                    = aws_rds_global_cluster.global_aurora_mysql.engine
  global_cluster_identifier = aws_rds_global_cluster.global_aurora_mysql.id
  kms_key_id                = aws_kms_key.one_rds.arn
  skip_final_snapshot       = true

  instance_class = "db.r5.large"
  instances = { 
    one = {}
    two = {}
  }

  vpc_id                 = module.one_vpc.vpc_id
  create_db_subnet_group = false
  db_subnet_group_name   = module.one_vpc.database_subnet_group_name

  create_security_group = true
  security_group_rules = {
    ingress = {
      cidr_blocks = module.one_vpc.private_subnets_cidr_blocks
    }
  }

  manage_master_user_password = false
  master_username             = "admin"
  master_password             = "adminadmin"
}

module "two_aurora_mysql" {
  providers = {
    aws = aws.two
  }
  source = "terraform-aws-modules/rds-aurora/aws"

  name = format("%s-two-aurora", local.name)

  engine                    = aws_rds_global_cluster.global_aurora_mysql.engine
  global_cluster_identifier = aws_rds_global_cluster.global_aurora_mysql.id
  kms_key_id                = aws_kms_key.two_rds.arn
  is_primary_cluster        = false
  skip_final_snapshot       = true

  instance_class = "db.r5.large"
  instances = { 
    one = {}
    two = {}
  }

  vpc_id                 = module.two_vpc.vpc_id
  create_db_subnet_group = false
  db_subnet_group_name   = module.two_vpc.database_subnet_group_name

  create_security_group = true
  security_group_rules = {
    ingress = {
      cidr_blocks = module.two_vpc.private_subnets_cidr_blocks
    }
  }
}


data "aws_iam_policy_document" "kms_rds" {
  provider = aws.one

  statement {
    sid       = "Enable IAM User Permissions"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type = "AWS"
      identifiers = [
        "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
        data.aws_caller_identity.current.arn,
      ]
    }
  }

  statement {
    sid = "Allow use of the key"
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey"
    ]
    resources = ["*"]

    principals {
      type = "Service"
      identifiers = [
        "monitoring.rds.amazonaws.com",
        "rds.amazonaws.com",
      ]
    }
  }
}

resource "aws_kms_key" "one_rds" {
  provider = aws.one

  policy = data.aws_iam_policy_document.kms_rds.json
  tags = {
    Name = format("%s-one-rds", local.name)
  }
}

resource "aws_kms_key" "two_rds" {
  provider = aws.two

  policy = data.aws_iam_policy_document.kms_rds.json
  tags = {
    Name = format("%s-one-rds", local.name)
  }
}

## EKS One
module "one_eks" {
  providers = {
    aws = aws.one
    kubernetes = kubernetes.one
  }
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-one-eks", local.name)

  vpc_id                         = module.one_vpc.vpc_id
  subnet_ids                     = module.one_vpc.private_subnets
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

      taints = {
        dedicated = {
          key    = "type"
          value  = "control"
          effect = "NO_SCHEDULE"
        }
      }
    }
  }

  ## Node Security Group
  node_security_group_tags = {
    "karpenter.sh/discovery" = format("%s-one-eks", local.name) # for Karpenter
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
      rolearn  = module.one_karpenter.role_arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups = [
        "system:bootstrappers",
        "system:nodes",
      ]
    },
  ]
}

## EKS One / Addons
module "one_eks_blueprints_addons" {
  providers = {
    aws = aws.one
    kubernetes = kubernetes.one
  }
  source  = "aws-ia/eks-blueprints-addons/aws"

  cluster_name      = module.one_eks.cluster_name
  cluster_endpoint  = module.one_eks.cluster_endpoint
  cluster_version   = module.one_eks.cluster_version
  oidc_provider_arn = module.one_eks.oidc_provider_arn

  eks_addons = {
    coredns = {
      most_recent = true
      configuration_values = jsonencode({
        nodeSelector: {
          type: "control"
        }
        tolerations: [
          {
            key: "type",
            value: "control",
            operator: "Equal",
            effect: "NoSchedule"
          }
        ]
      })
    }
    vpc-cni = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
  }
}

## EKS One / Karpenter
module "one_karpenter" {
  providers = {
    aws = aws.one
    kubernetes = kubernetes.one
  }
  source = "terraform-aws-modules/eks/aws//modules/karpenter"

  cluster_name = module.one_eks.cluster_name

  irsa_oidc_provider_arn       = module.one_eks.oidc_provider_arn
  iam_role_additional_policies = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
}

resource "helm_release" "one_karpenter" {
  provider = helm.one

  namespace        = "karpenter"
  create_namespace = true

  name       = "karpenter"
  chart      = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  version    = "v0.24.0"

  set {
    name  = "settings.aws.clusterName"
    value = module.one_eks.cluster_name
  }
  set {
    name  = "settings.aws.clusterEndpoint"
    value = module.one_eks.cluster_endpoint
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.one_karpenter.irsa_arn
  }
  set {
    name  = "settings.aws.defaultInstanceProfile"
    value = module.one_karpenter.instance_profile_name
  }
  set {
    name  = "settings.aws.interruptionQueueName"
    value = module.one_karpenter.queue_name
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
  set {
    name  = "tolerations[0].key"
    value = "type"
  }
  set {
    name  = "tolerations[0].value"
    value = "control"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
  } 
}

resource "kubectl_manifest" "one_karpenter_provisioner" {
  provider = kubectl.one

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
    helm_release.one_karpenter
  ]
}

resource "kubectl_manifest" "one_karpenter_node_template" {
  provider = kubectl.one

  yaml_body = <<-YAML
    apiVersion: karpenter.k8s.aws/v1alpha1
    kind: AWSNodeTemplate
    metadata:
      name: default
    spec:
      subnetSelector:
        karpenter.sh/discovery: ${format("%s-eks", local.name)}
      securityGroupSelector:
        karpenter.sh/discovery: ${format("%s-one-eks", local.name)}
      tags:
        karpenter.sh/discovery: ${format("%s-one-eks", local.name)}
  YAML

  depends_on = [
    helm_release.one_karpenter
  ]
}

## EKS One / Load Balancer Controller
module "one_eks_load_balancer_controller_irsa_role" {
  providers = {
    aws = aws.one
  }
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-one-eks-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.one_eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "one_aws_load_balancer_controller" {
  provider = helm.one

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
 
  set {
    name  = "clusterName"
    value = module.one_eks.cluster_name
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.one_eks_load_balancer_controller_irsa_role.iam_role_arn
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
  set {
    name  = "tolerations[0].key"
    value = "type"
  }
  set {
    name  = "tolerations[0].value"
    value = "control"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
  }
}

## EKS One / External DNS
module "one_eks_external_dns_irsa_role" {
  providers = {
    aws = aws.one
  }
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                  = format("%s-one-eks-external-dns", local.name)
  attach_external_dns_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.one_eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
}

resource "helm_release" "one_external_dns" {
  provider = helm.one

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
    value = module.one_eks_external_dns_irsa_role.iam_role_arn
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
  set {
    name  = "tolerations[0].key"
    value = "type"
  }
  set {
    name  = "tolerations[0].value"
    value = "control"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
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

## EKS One / EFS CSI
module "one_eks_efs_csi_irsa_role" {
  providers = {
    aws = aws.one
  }
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-one-eks-efs-csi", local.name)
  attach_efs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.one_eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:efs-csi-controller-sa"]
    }
  }
}

resource "helm_release" "one_aws_efs_csi_driver" {
  provider = helm.one

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
    value = module.one_eks_efs_csi_irsa_role.iam_role_arn
  }
  set {
    name  = "controller.nodeSelector.type"
    value = "control"
  }
  set {
    name  = "controller.tolerations[0].key"
    value = "type"
  }
  set {
    name  = "controller.tolerations[0].value"
    value = "control"
  }
  set {
    name  = "controller.tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "controller.tolerations[0].effect"
    value = "NoSchedule"
  }
}

resource "kubectl_manifest" "one_efs_pv" {
  provider = kubectl.one

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
        volumeHandle: ${aws_efs_file_system.one_efs.id}
  YAML

  depends_on = [
    helm_release.one_aws_efs_csi_driver
  ]
}

resource "kubectl_manifest" "one_efs_pvc" {
  provider = kubectl.one

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
    helm_release.one_aws_efs_csi_driver
  ]
}

resource "kubectl_manifest" "one_efs_sc" {
  provider = kubectl.one

  yaml_body = <<-YAML
    apiVersion: storage.k8s.io/v1
    kind: StorageClass
    metadata:
      name: efs-sc
    provisioner: efs.csi.aws.com
  YAML

  depends_on = [
    helm_release.one_aws_efs_csi_driver
  ]
}

## EKS Two
module "two_eks" {
  providers = {
    aws = aws.two
    kubernetes = kubernetes.two
  }
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-two-eks", local.name)

  vpc_id                         = module.two_vpc.vpc_id
  subnet_ids                     = module.two_vpc.private_subnets
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

      taints = {
        dedicated = {
          key    = "type"
          value  = "control"
          effect = "NO_SCHEDULE"
        }
      }
    }
  }

  ## Node Security Group
  node_security_group_tags = {
    "karpenter.sh/discovery" = format("%s-two-eks", local.name) # for Karpenter
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
      rolearn  = module.two_karpenter.role_arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups = [
        "system:bootstrappers",
        "system:nodes",
      ]
    },
  ]
}

## EKS Two / Addons
module "two_eks_blueprints_addons" {
  providers = {
    aws = aws.two
    kubernetes = kubernetes.two
  }
  source  = "aws-ia/eks-blueprints-addons/aws"

  cluster_name      = module.two_eks.cluster_name
  cluster_endpoint  = module.two_eks.cluster_endpoint
  cluster_version   = module.two_eks.cluster_version
  oidc_provider_arn = module.two_eks.oidc_provider_arn

  eks_addons = {
    coredns = {
      most_recent = true
      configuration_values = jsonencode({
        nodeSelector: {
          type: "control"
        }
        tolerations: [
          {
            key: "type",
            value: "control",
            operator: "Equal",
            effect: "NoSchedule"
          }
        ]
      })
    }
    vpc-cni = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
  }
}

## EKS Two / Karpenter
module "two_karpenter" {
  providers = {
    aws = aws.two
    kubernetes = kubernetes.two
  }
  source = "terraform-aws-modules/eks/aws//modules/karpenter"

  cluster_name = module.two_eks.cluster_name

  irsa_oidc_provider_arn       = module.two_eks.oidc_provider_arn
  iam_role_additional_policies = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
}

resource "helm_release" "two_karpenter" {
  provider = helm.two

  namespace        = "karpenter"
  create_namespace = true

  name       = "karpenter"
  chart      = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  version    = "v0.24.0"

  set {
    name  = "settings.aws.clusterName"
    value = module.two_eks.cluster_name
  }
  set {
    name  = "settings.aws.clusterEndpoint"
    value = module.two_eks.cluster_endpoint
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.two_karpenter.irsa_arn
  }
  set {
    name  = "settings.aws.defaultInstanceProfile"
    value = module.two_karpenter.instance_profile_name
  }
  set {
    name  = "settings.aws.interruptionQueueName"
    value = module.two_karpenter.queue_name
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
  set {
    name  = "tolerations[0].key"
    value = "type"
  }
  set {
    name  = "tolerations[0].value"
    value = "control"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
  }
  set {
    name  = "replicas"
    value = "0"
  }
}

resource "kubectl_manifest" "two_karpenter_provisioner" {
  provider = kubectl.two

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
    helm_release.two_karpenter
  ]
}

resource "kubectl_manifest" "two_karpenter_node_template" {
  provider = kubectl.two

  yaml_body = <<-YAML
    apiVersion: karpenter.k8s.aws/v1alpha1
    kind: AWSNodeTemplate
    metadata:
      name: default
    spec:
      subnetSelector:
        karpenter.sh/discovery: ${format("%s-eks", local.name)}
      securityGroupSelector:
        karpenter.sh/discovery: ${format("%s-two-eks", local.name)}
      tags:
        karpenter.sh/discovery: ${format("%s-two-eks", local.name)}
  YAML

  depends_on = [
    helm_release.two_karpenter
  ]
}

## EKS Two / Load Balancer Controller
module "two_eks_load_balancer_controller_irsa_role" {
  providers = {
    aws = aws.two
  }
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("eks-aws-load-balancer-controller-%s", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.two_eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "two_aws_load_balancer_controller" {
  provider = helm.two

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
 
  set {
    name  = "clusterName"
    value = module.two_eks.cluster_name
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.two_eks_load_balancer_controller_irsa_role.iam_role_arn
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
  set {
    name  = "tolerations[0].key"
    value = "type"
  }
  set {
    name  = "tolerations[0].value"
    value = "control"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
  }
}

## EKS Two / External DNS
module "two_eks_external_dns_irsa_role" {
  providers = {
    aws = aws.two
  }
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                  = format("eks-external-dns-%s", local.name)
  attach_external_dns_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.two_eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
}

resource "helm_release" "two_external_dns" {
  provider = helm.two

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
    value = module.two_eks_external_dns_irsa_role.iam_role_arn
  }
  set {
    name  = "nodeSelector.type"
    value = "control"
  }
  set {
    name  = "tolerations[0].key"
    value = "type"
  }
  set {
    name  = "tolerations[0].value"
    value = "control"
  }
  set {
    name  = "tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "tolerations[0].effect"
    value = "NoSchedule"
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

## EKS Two / EFS CSI
module "two_eks_efs_csi_irsa_role" {
  providers = {
    aws = aws.two
  }
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("eks-efs-csi-%s", local.name)
  attach_efs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.two_eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:efs-csi-controller-sa"]
    }
  }
}

resource "helm_release" "two_aws_efs_csi_driver" {
  provider = helm.two

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
    value = module.two_eks_efs_csi_irsa_role.iam_role_arn
  }
  set {
    name  = "controller.nodeSelector.type"
    value = "control"
  }
  set {
    name  = "controller.tolerations[0].key"
    value = "type"
  }
  set {
    name  = "controller.tolerations[0].value"
    value = "control"
  }
  set {
    name  = "controller.tolerations[0].operator"
    value = "Equal"
  }
  set {
    name  = "controller.tolerations[0].effect"
    value = "NoSchedule"
  }
}

resource "kubectl_manifest" "two_efs_pv" {
  provider = kubectl.two

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
        volumeHandle: ${aws_efs_replication_configuration.two_efs.destination[0].file_system_id}
  YAML

  depends_on = [
    helm_release.two_aws_efs_csi_driver
  ]
}

resource "kubectl_manifest" "two_efs_pvc" {
  provider = kubectl.two

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
    helm_release.two_aws_efs_csi_driver
  ]
}

resource "kubectl_manifest" "two_efs_sc" {
  provider = kubectl.two

  yaml_body = <<-YAML
    apiVersion: storage.k8s.io/v1
    kind: StorageClass
    metadata:
      name: efs-sc
    provisioner: efs.csi.aws.com
  YAML

  depends_on = [
    helm_release.two_aws_efs_csi_driver
  ]
}

