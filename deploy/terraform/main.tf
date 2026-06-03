terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket = "ddos-detection-tfstate"
    key    = "terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.aws_region
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  name    = "${var.project_name}-vpc"
  cidr    = var.vpc_cidr
  azs     = var.availability_zones
  private_subnets = var.private_subnets
  public_subnets  = var.public_subnets
  enable_nat_gateway = true
  single_nat_gateway = var.environment != "production"
  tags = var.tags
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"
  cluster_name    = "${var.project_name}-cluster"
  cluster_version = "1.28"
  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets
  eks_managed_node_groups = {
    detection = {
      min_size     = 2
      max_size     = 10
      desired_size = 3
      instance_types = ["m5.xlarge"]
    }
  }
  tags = var.tags
}
