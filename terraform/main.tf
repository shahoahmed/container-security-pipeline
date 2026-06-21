terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  description = "AWS region to deploy resources into"
  type        = string
  default     = "us-east-1"
}

variable "repository_name" {
  description = "Name of the ECR repository for the compliance demo app"
  type        = string
  default     = "compliance-demo-app"
}

# Immutable tags + scan-on-push close the loop between this repo's CI scan
# and the registry's own scan, so a finding can't slip through if someone
# pushes an image outside the pipeline.
resource "aws_ecr_repository" "compliance_demo" {
  name                 = var.repository_name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
  }

  tags = {
    Project    = "container-security-pipeline"
    Compliance = "NIST-800-171"
  }
}

# NIST 800-171 3.4.2 / 3.11.2 — keep the registry from accumulating stale,
# unscanned images that nobody is tracking.
resource "aws_ecr_lifecycle_policy" "cleanup" {
  repository = aws_ecr_repository.compliance_demo.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images older than 14 days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 14
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}

output "repository_url" {
  description = "URL of the ECR repository"
  value       = aws_ecr_repository.compliance_demo.repository_url
}
