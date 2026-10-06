# ==========================================
# 1. Amazon S3 Buckets
# ==========================================

# Vulnerable Bucket: Unencrypted, no Public Access Block
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "vulnerable-customer-data-bucket"
  force_destroy = true

  tags = {
    Environment = "LocalStack-Dev"
    SecurityRisk = "High"
  }
}

# Compliant Bucket: SSE-S3 Encrypted and Public Access Blocked
resource "aws_s3_bucket" "compliant_bucket" {
  bucket        = "secure-encrypted-backup-bucket"
  force_destroy = true

  tags = {
    Environment = "LocalStack-Prod"
    Compliance  = "CIS-Pass"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant_encryption" {
  bucket = aws_s3_bucket.compliant_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "compliant_pab" {
  bucket = aws_s3_bucket.compliant_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ==========================================
# 2. AWS IAM Roles
# ==========================================

# Vulnerable IAM Role: Wildcard AdministratorAccess attached
resource "aws_iam_role" "insecure_admin_role" {
  name = "insecure-app-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "admin_attach" {
  role       = aws_iam_role.insecure_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Compliant IAM Role: Scoped ReadOnly permissions
resource "aws_iam_role" "compliant_read_role" {
  name = "compliant-readonly-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "readonly_attach" {
  role       = aws_iam_role.compliant_read_role.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ==========================================
# 3. Amazon EC2 / VPC Security Groups
# ==========================================

# Insecure Security Group: Open SSH (0.0.0.0/0 to port 22)
resource "aws_security_group" "insecure_ssh_sg" {
  name        = "insecure-ssh-sg"
  description = "Security group with open SSH from 0.0.0.0/0"

  ingress {
    description = "SSH from everywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    SecurityAudit = "Failed-SSH"
  }
}

# Compliant Security Group: Restricted HTTPS only
resource "aws_security_group" "compliant_web_sg" {
  name        = "compliant-web-sg"
  description = "Security group restricting ingress to HTTPS"

  ingress {
    description = "HTTPS ingress"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    SecurityAudit = "Passed-HTTPS"
  }
}

# ==========================================
# 4. Agent Execution Role & Permissions Boundary
# ==========================================

resource "aws_iam_policy" "agent_permissions_boundary" {
  name        = "agent-permissions-boundary"
  description = "Permissions boundary for the autonomous security agent to prevent privilege escalation (OWASP LLM06)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSpecificServices"
        Effect = "Allow"
        Action = [
          "s3:*",
          "ec2:*",
          "securityhub:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyIAMModificationsToSelf"
        Effect = "Deny"
        Action = [
          "iam:PutRolePolicy",
          "iam:AttachRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:DetachRolePolicy",
          "iam:UpdateAssumeRolePolicy"
        ]
        Resource = "arn:aws:iam::*:role/agent-execution-role"
      },
      {
        Sid    = "RestrictPassRole"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          "arn:aws:iam::*:role/compliant-readonly-role"
        ]
      }
    ]
  })
}

resource "aws_iam_role" "agent_execution_role" {
  name = "agent-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  permissions_boundary = aws_iam_policy.agent_permissions_boundary.arn
}

