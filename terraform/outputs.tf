output "vulnerable_bucket_arn" {
  description = "ARN of the unencrypted S3 bucket"
  value       = aws_s3_bucket.vulnerable_bucket.arn
}

output "compliant_bucket_arn" {
  description = "ARN of the encrypted S3 bucket"
  value       = aws_s3_bucket.compliant_bucket.arn
}

output "insecure_admin_role_arn" {
  description = "ARN of the overprivileged IAM role"
  value       = aws_iam_role.insecure_admin_role.arn
}

output "insecure_security_group_id" {
  description = "Security group ID allowing open SSH port 22"
  value       = aws_security_group.insecure_ssh_sg.id
}
