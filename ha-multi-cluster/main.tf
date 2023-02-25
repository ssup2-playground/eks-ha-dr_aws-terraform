## Provider
provider "aws" {
  region = local.region
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
data "aws_availability_zones" "available" {}

## Local Vars
locals {
  name = "eks-ha-multi"

  region   = "ap-southeast-1"
  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
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
  source  = "terraform-aws-modules/vpc/aws"

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
  skip_final_snapshot = false

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

## EKS One
module "one_eks" {
  providers = {
    kubernetes = kubernetes.one
  }
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-one-eks", local.name)

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

## EKS One / Karpenter
module "one_karpenter" {
  providers = {
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
        - key: "topology.kubernetes.io/zone"
          operator: In
          values: ["ap-southeast-1a"]
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
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

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
}

## EKS One / External DNS
module "one_eks_external_dns_irsa_role" {
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
        volumeHandle: ${module.efs.id}
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
    kubernetes = kubernetes.two
  }
  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-two-eks", local.name)

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

## EKS Two / Karpenter
module "two_karpenter" {
  providers = {
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
        - key: "topology.kubernetes.io/zone"
          operator: In
          values: ["ap-southeast-1b"]
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
}

## EKS Two / External DNS
module "two_eks_external_dns_irsa_role" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

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
        volumeHandle: ${module.efs.id}
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

