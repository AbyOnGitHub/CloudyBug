package cloud.security.agent

import future.keywords.in

default allow = false

allow {
    not deny
}

# Deny attaching AdministratorAccess policy to any role
deny {
    input.action == "iam:AttachRolePolicy"
    endswith(input.policy_arn, "AdministratorAccess")
}

# Deny deletion of critical data sources in production
deny {
    startswith(input.action, "s3:Delete")
    input.environment == "production"
}

# Deny deletion of critical databases in production
deny {
    startswith(input.action, "rds:Delete")
    input.environment == "production"
}

# Deny setting IMDS to optional
deny {
    input.action == "ec2:ModifyInstanceMetadataOptions"
    input.http_tokens == "optional"
}

# Explicitly allow safe read actions
allow {
    startswith(input.action, "s3:Get")
}
allow {
    startswith(input.action, "s3:List")
}
allow {
    startswith(input.action, "iam:Get")
}
allow {
    startswith(input.action, "iam:List")
}

# Allow modifying tags
allow {
    input.action == "ec2:CreateTags"
}
