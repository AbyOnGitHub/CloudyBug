#!/usr/bin/env bash
set -eo pipefail

echo "Initializing LocalStack resources for Prowler Security Scanning..."

# 1. Create S3 Buckets
echo "Creating S3 Buckets in LocalStack..."
awslocal s3 mb s3://vulnerable-customer-data-bucket --region us-east-1
awslocal s3 mb s3://secure-encrypted-backup-bucket --region us-east-1

# Enable SSE-S3 encryption on compliant bucket
awslocal s3api put-bucket-encryption \
  --bucket secure-encrypted-backup-bucket \
  --server-side-encryption-configuration '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'

# Enable Public Access Block on compliant bucket
awslocal s3api put-public-access-block \
  --bucket secure-encrypted-backup-bucket \
  --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 2. Create IAM Roles
echo "Creating IAM Roles in LocalStack..."
awslocal iam create-role \
  --role-name insecure-app-admin-role \
  --assume-role-policy-document '{"Version": "2012-10-17", "Statement": [{"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}}]}'

# Attach wildcard AdministratorAccess to insecure role
awslocal iam attach-role-policy \
  --role-name insecure-app-admin-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create compliant scoped role
awslocal iam create-role \
  --role-name compliant-readonly-role \
  --assume-role-policy-document '{"Version": "2012-10-17", "Statement": [{"Action": "sts:AssumeRole", "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}}]}'

awslocal iam attach-role-policy \
  --role-name compliant-readonly-role \
  --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# 3. Create EC2 Security Groups
echo "Creating EC2 Security Groups in LocalStack..."
SG_INSECURE=$(awslocal ec2 create-security-group \
  --group-name insecure-ssh-sg \
  --description "Insecure SG with open port 22" \
  --query 'GroupId' --output text)

# Authorize 0.0.0.0/0 on port 22
awslocal ec2 authorize-security-group-ingress \
  --group-id "$SG_INSECURE" \
  --protocol tcp \
  --port 22 \
  --cidr 0.0.0.0/0

echo "LocalStack resources initialized successfully!"
