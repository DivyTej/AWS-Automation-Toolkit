# Function to check the current AWS identity (whoami)
function Check-Identity {
    try {
        if (-not $awsRegion) {
            Write-Host "Region is not set. Please set a valid AWS region." -ForegroundColor Red
            return
        }

        $identity = aws sts get-caller-identity --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
        Write-Host "AWS Identity Information:" -ForegroundColor Cyan
        Write-Host "UserId: $($identity.UserId)" -ForegroundColor Cyan
        Write-Host "Account: $($identity.Account)" -ForegroundColor Cyan
        Write-Host "Arn: $($identity.Arn)" -ForegroundColor Cyan
    } catch {
        Write-Host "An error occurred while fetching identity: $_" -ForegroundColor Red
    }
}

# Function to check IAM users' last login and MFA status
function Check-IAMUsers {
    try {
        $daysThreshold = Read-Host "Enter the number of days to check for inactivity"
        $thresholdDate = (Get-Date).AddDays(-$daysThreshold)

        # List users
        $users = aws iam list-users --query "Users[*].UserName" --output text --profile $selectedProfile --region $awsRegion
        $users = $users -split '\t'

        # Check if there are no users
        if ($users.Count -eq 0) {
            Write-Host "No IAM users found." -ForegroundColor Yellow
            return  # Exit the function if no users are found
        }

        # Add the root user as a special case
        $rootUser = "root"
        $users = $users + $rootUser  # Include the root account in the list

        foreach ($username in $users) {
            Write-Host "Checking user: $username" -ForegroundColor Cyan

            # Handle the root user separately
            if ($username -eq $rootUser) {
                # For root account, check MFA and inactivity
                $mfaDevices = aws iam list-mfa-devices --user-name $rootUser --query "MFADevices" --output json --profile $selectedProfile --region $awsRegion
                $mfaEnabled = if ($mfaDevices -eq "[]") { "MFA is not enabled." } else { "MFA is enabled." }
                
                # Check if the root account has been used (root account doesn't have PasswordLastUsed)
                $rootStatus = "Root account activity not tracked by PasswordLastUsed."
                
                Write-Host "$rootStatus" -ForegroundColor Cyan
                Write-Host "$mfaEnabled" -ForegroundColor Cyan
                Write-Host "---------------------------------------------" -ForegroundColor Cyan
                Write-Host ""
                continue
            }

            # For regular IAM users, perform regular checks (last login, access keys, etc.)
            # Get user details (last password used)
            $userDetails = aws iam get-user --user-name $username --query "User.PasswordLastUsed" --output text --profile $selectedProfile --region $awsRegion
            $userLastLogin = if ($userDetails -ne "None") { [datetime]::Parse($userDetails) } else { $null }

            # List and check access keys
            $accessKeys = aws iam list-access-keys --user-name $username --query "AccessKeyMetadata[*].{AccessKeyId:AccessKeyId,Status:Status,CreateDate:CreateDate}" --output json --profile $selectedProfile --region $awsRegion
            $accessKeyUsed = $null
            if ($accessKeys -ne "[]") {
                $accessKeyMetadata = $accessKeys | ConvertFrom-Json
                foreach ($accessKey in $accessKeyMetadata) {
                    if ($accessKey.Status -eq "Active") {
                        $accessKeyLastUsed = aws iam get-access-key-last-used --access-key-id $accessKey.AccessKeyId --query "AccessKeyLastUsed.LastUsedDate" --output text --profile $selectedProfile --region $awsRegion
                        if ($accessKeyLastUsed -ne "None") {
                            $accessKeyUsed = [datetime]::Parse($accessKeyLastUsed)
                        }
                    }
                }
            }

            # List MFA devices and handle empty response correctly
            $mfaDevices = aws iam list-mfa-devices --user-name $username --query "MFADevices" --output json --profile $selectedProfile --region $awsRegion
            $mfaEnabled = if ($mfaDevices -eq "[]") { "MFA is not enabled." } else { "MFA is enabled." }

            # Output the results
            $lastLoginOutput = if ($userLastLogin) { "Last password login: $($userLastLogin.ToString('yyyy-MM-dd HH:mm:ss'))" } else { "No password login recorded." }
            $lastAccessKeyOutput = if ($accessKeyUsed) { "Last access key usage: $($accessKeyUsed.ToString('yyyy-MM-dd HH:mm:ss'))" } else { "No access key usage recorded." }

            # Determine inactivity message
            $inactivityMessage = if ((!$userLastLogin -or $userLastLogin -lt $thresholdDate) -and (!$accessKeyUsed -or $accessKeyUsed -lt $thresholdDate)) {
                "User has not logged in or used access keys for more than $daysThreshold days."
            } else {
                "User has been active within the last $daysThreshold days."
            }

            # Display information
            Write-Host "$username" -ForegroundColor Cyan
            Write-Host "$inactivityMessage" -ForegroundColor Cyan
            Write-Host "$lastLoginOutput" -ForegroundColor Cyan
            Write-Host "$lastAccessKeyOutput" -ForegroundColor Cyan
            Write-Host "$mfaEnabled" -ForegroundColor Cyan
            Write-Host "---------------------------------------------" -ForegroundColor Cyan
            Write-Host ""
        }
    } catch {
        Write-Host "An error occurred while fetching IAM user details: $_" -ForegroundColor Red
    }
}

# Function to check security for Lambda functions
function Check-LambdaSecurity {
    param (
        [string]$LambdaFunctionName,
        [string]$selectedProfile
    )

    # Fetch Lambda function details
    Write-Host "Fetching Lambda functions..." -ForegroundColor Cyan
    try {
        $lambdaFunctions = if ($LambdaFunctionName -eq "*") {
            $functions = aws lambda list-functions --query "Functions[*].FunctionName" --output json --profile $selectedProfile
        } else {
            $functions = @($LambdaFunctionName)
        }

        $lambdaFunctions = $functions | ConvertFrom-Json

        if ($lambdaFunctions.Count -eq 0) {
            Write-Host "No Lambda functions found in your AWS account." -ForegroundColor Yellow
            return
        }

        # Loop through each Lambda function
        foreach ($lambdaFunction in $lambdaFunctions) {
            Write-Host "`nChecking security for Lambda function: $lambdaFunction..." -ForegroundColor Cyan

            # Fetch function details
            $functionDetails = aws lambda get-function --function-name $lambdaFunction --query "Configuration" --output json --profile $selectedProfile
            $functionDetails = $functionDetails | ConvertFrom-Json

            # 1. Check IAM Role Permissions
            $iamRole = $functionDetails.Role
            Write-Host " - IAM Role: $iamRole"

            $iamRoleDetails = aws iam get-role --role-name (Split-Path -Leaf $iamRole) --query "Role.Policies" --output json --profile $selectedProfile
            $iamRoleDetails = $iamRoleDetails | ConvertFrom-Json
            if ($iamRoleDetails -eq $null) {
                Write-Host "   - IAM role has no policies attached, potentially dangerous." -ForegroundColor Yellow
            } else {
                Write-Host "   - IAM role has policies attached." -ForegroundColor Green
            }

            # 2. Check if the Lambda has public triggers (e.g., API Gateway, SNS)
            $triggers = aws lambda list-event-source-mappings --function-name $lambdaFunction --query "EventSourceMappings[*].EventSourceArn" --output json --profile $selectedProfile
            $triggers = $triggers | ConvertFrom-Json
            if ($triggers.Count -gt 0) {
                Write-Host "   - Lambda function has triggers: $($triggers -join ', ')" -ForegroundColor Green
            } else {
                Write-Host "   - No public triggers found." -ForegroundColor Yellow
            }

            # 3. Check Environment Variables for Sensitive Data
            if ($functionDetails.Environment -and $functionDetails.Environment.Variables) {
                $envVariables = $functionDetails.Environment.Variables
                Write-Host "   - Environment Variables found." -ForegroundColor Yellow
                foreach ($key in $envVariables.Keys) {
                    Write-Host "     - ${key}: $($envVariables[$key])" -ForegroundColor White
                }
            } else {
                Write-Host "   - No environment variables found." -ForegroundColor Green
            }

            # 4. Check Timeout and Memory Settings
            $timeout = $functionDetails.Timeout
            $memorySize = $functionDetails.MemorySize
            Write-Host "   - Timeout: $timeout seconds"
            Write-Host "   - Memory Size: $memorySize MB"
            if ($timeout -gt 300) {
                Write-Host "     - Timeout is unusually high. Consider reducing." -ForegroundColor Yellow
            }
            if ($memorySize -gt 1024) {
                Write-Host "     - Memory size is unusually high. Consider reducing." -ForegroundColor Yellow
            }

            # 5. Check Lambda Layers
            $layers = $functionDetails.Layers
            if ($layers) {
                Write-Host "   - Lambda function uses the following layers:" -ForegroundColor Green
                foreach ($layer in $layers) {
                    Write-Host "     - Layer ARN: $($layer.Arn)" -ForegroundColor White
                }
            } else {
                Write-Host "   - No Lambda layers attached." -ForegroundColor Green
            }

            # 6. Check CloudWatch Logs for Logging Configuration
            $logGroupName = "/aws/lambda/$lambdaFunction"
            $logs = aws logs describe-log-groups --log-group-name-prefix $logGroupName --query "logGroups[*].logGroupName" --output json --profile $selectedProfile
            $logs = $logs | ConvertFrom-Json
            if ($logs) {
                Write-Host "   - CloudWatch Logs are configured." -ForegroundColor Green
            } else {
                Write-Host "   - CloudWatch Logs are not configured. Consider enabling logging." -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "An error occurred while fetching Lambda functions or details. Please check your AWS CLI configuration." -ForegroundColor Red
    }
}

# Function to check for publicly accessible S3 buckets in all regions
function Check-PublicS3Buckets {
    try {
        # Save the original/default region before checking others
        $defaultRegion = $awsRegion

        # Get list of all available regions
        $regions = aws ec2 describe-regions --query "Regions[*].RegionName" --output text --profile $selectedProfile --region $defaultRegion
        $regions = $regions -split '\s+'

        # If no regions found, exit the function
        if ($regions.Count -eq 0) {
            Write-Host "No regions found." -ForegroundColor Red
            return
        }

        # Define the bucket names you're interested in
        $bucketNamesToCheck = @(
            'codepipeline-ap-south-1-272671467365',
            'gas-alb-logs-po',
            'gas-log-bucket',
            'gas-survey',
            'skjfnhsf-3bwkfkjk'
        )

        # Loop through each region
        foreach ($region in $regions) {
            Write-Host "Checking region ${region}" -ForegroundColor Cyan

            # Set the region for the AWS CLI command
            $awsRegion = $region

            try {
                # Attempt to list the buckets in the current region
                Write-Host "Listing buckets in region: ${awsRegion}..." -ForegroundColor Yellow
                $buckets = aws s3api list-buckets --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
                
                # Ensure there are buckets returned
                if ($buckets.Buckets -and $buckets.Buckets.Name) {
                    Write-Host "Buckets found in region ${awsRegion}:" -ForegroundColor Green
                    $buckets.Buckets.Name | ForEach-Object { Write-Host $_ -ForegroundColor Green }
                    
                    # Check if any of the specified buckets exist in the region
                    $bucketExists = $false
                    foreach ($bucketName in $bucketNamesToCheck) {
                        if ($buckets.Buckets.Name -contains $bucketName) {
                            $bucketExists = $true
                            Write-Host "Bucket found: ${bucketName}" -ForegroundColor Cyan

                            # Check Bucket ACL for public access
                            $bucketAcl = aws s3api get-bucket-acl --bucket $bucketName --profile $selectedProfile --region $awsRegion | ConvertFrom-Json

                            # Check if "AllUsers" is included in the permissions
                            $publicAccessGrant = $bucketAcl.Grants | Where-Object { 
                                $_.Grantee.Type -eq "CanonicalUser" -and $_.Grantee.URI -eq "http://acs.amazonaws.com/groups/global/AllUsers"
                            }

                            if ($publicAccessGrant) {
                                Write-Host "Warning: Bucket ${bucketName} is publicly accessible" -ForegroundColor Red
                            } else {
                                Write-Host "Bucket ${bucketName} is not publicly accessible" -ForegroundColor Green
                            }
                        }
                    }

                    if (-not $bucketExists) {
                        Write-Host "None of the specified buckets found in region ${awsRegion}" -ForegroundColor Yellow
                    }
                } else {
                    Write-Host "No buckets found in region ${awsRegion}" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "Error listing buckets or checking ACL in region ${region}: $_" -ForegroundColor Red
            }

            # Add a line break after checking each region
            Write-Host "`n" -ForegroundColor Cyan
        }

        # After checking all regions, reset the region to the default region
        $awsRegion = $defaultRegion
        Write-Host "Region has been reset to the default region: ${defaultRegion}" -ForegroundColor Green

    } catch {
        Write-Host "An error occurred while checking public S3 buckets: $_" -ForegroundColor Red
    }
}

# Function to enumerate IAM user and role managed policies
function Enumerate-ManagedPolicies {
    param (
        [string]$EntityName = '*'  # Default to '*' for all users/roles
    )
    try {
        Write-Host "Fetching managed policies..." -ForegroundColor Cyan

        # Define a list of dangerous policies or actions
        $dangerousActions = @(
            "iam:CreatePolicy",
            "iam:PutRolePolicy",
            "iam:AttachRolePolicy",
            "iam:PassRole",
            "iam:AddUserToGroup",
            "sts:AssumeRole",
            "*"
        )

        function Is-DangerousPolicy($policyArn) {
            $policyDetails = aws iam get-policy --policy-arn $policyArn --output json --profile $selectedProfile | ConvertFrom-Json
            $policyVersion = aws iam get-policy-version --policy-arn $policyArn --version-id $policyDetails.Policy.DefaultVersionId --output json --profile $selectedProfile | ConvertFrom-Json

            foreach ($statement in $policyVersion.PolicyVersion.Document.Statement) {
                if ($statement.Action -contains "*" -or ($statement.Action | Where-Object { $dangerousActions -contains $_ })) {
                    return $true
                }
            }
            return $false
        }

        # Check if the user wants to fetch policies for all entities
        if ($EntityName -eq "*") {
            # Fetch all users and roles
            $users = aws iam list-users --output json --profile $selectedProfile | ConvertFrom-Json
            $roles = aws iam list-roles --output json --profile $selectedProfile | ConvertFrom-Json

            # Loop through users
            foreach ($user in $users.Users) {
                Write-Host "`nUser: $($user.UserName)" -ForegroundColor Yellow
                $userPolicies = aws iam list-attached-user-policies --user-name $user.UserName --output json --profile $selectedProfile | ConvertFrom-Json
                foreach ($policy in $userPolicies.AttachedPolicies) {
                    $isDangerous = Is-DangerousPolicy $policy.PolicyArn
                    if ($isDangerous) {
                        Write-Host "  Managed Policy: $($policy.PolicyName) ($($policy.PolicyArn)) [DANGEROUS]" -ForegroundColor Red
                    } else {
                        Write-Host "  Managed Policy: $($policy.PolicyName) ($($policy.PolicyArn))" -ForegroundColor Green
                    }
                }
            }

            # Loop through roles
            foreach ($role in $roles.Roles) {
                Write-Host "`nRole: $($role.RoleName)" -ForegroundColor Yellow
                $rolePolicies = aws iam list-attached-role-policies --role-name $role.RoleName --output json --profile $selectedProfile | ConvertFrom-Json
                foreach ($policy in $rolePolicies.AttachedPolicies) {
                    $isDangerous = Is-DangerousPolicy $policy.PolicyArn
                    if ($isDangerous) {
                        Write-Host "  Managed Policy: $($policy.PolicyName) ($($policy.PolicyArn)) [DANGEROUS]" -ForegroundColor Red
                    } else {
                        Write-Host "  Managed Policy: $($policy.PolicyName) ($($policy.PolicyArn))" -ForegroundColor Green
                    }
                }
            }
        } else {
            # Specific user or role
            # Try fetching user policies first
            $userPolicies = aws iam list-attached-user-policies --user-name $EntityName --output json --profile $selectedProfile | ConvertFrom-Json
            if ($userPolicies.AttachedPolicies.Count -gt 0) {
                Write-Host "`nUser: $EntityName" -ForegroundColor Yellow
                foreach ($policy in $userPolicies.AttachedPolicies) {
                    $isDangerous = Is-DangerousPolicy $policy.PolicyArn
                    if ($isDangerous) {
                        Write-Host "  Managed Policy: $($policy.PolicyName) ($($policy.PolicyArn)) [DANGEROUS]" -ForegroundColor Red
                    } else {
                        Write-Host "  Managed Policy: $($policy.PolicyName) ($($policy.PolicyArn))" -ForegroundColor Green
                    }
                }
            } else {
                # If no user policies, try fetching role policies
                $rolePolicies = aws iam list-attached-role-policies --role-name $EntityName --output json --profile $selectedProfile | ConvertFrom-Json
                if ($rolePolicies.AttachedPolicies.Count -gt 0) {
                    Write-Host "`nRole: $EntityName" -ForegroundColor Yellow
                    foreach ($policy in $rolePolicies.AttachedPolicies) {
                        $isDangerous = Is-DangerousPolicy $policy.PolicyArn
                        if ($isDangerous) {
                            Write-Host "  Managed Policy: $($policy.PolicyName) ($($policy.PolicyArn)) [DANGEROUS]" -ForegroundColor Red
                        } else {
                            Write-Host "  Managed Policy: $($policy.PolicyName) ($($policy.PolicyArn))" -ForegroundColor Green
                        }
                    }
                } else {
                    Write-Host "`n$EntityName not found as a User or Role or does not have any attached managed policies." -ForegroundColor Red
                }
            }
        }
    } catch {
        Write-Host "An error occurred while enumerating managed policies: $_" -ForegroundColor Red
    }
}

# Function to enumerate IAM user and role inline policies
function Enumerate-InlinePolicies {
    param (
        [string]$EntityName = '*'  # Default to '*' for all users/roles
    )
    
    try {
        Write-Host "Fetching inline policies..." -ForegroundColor Cyan

        # Define a list of dangerous actions or keywords
        $dangerousActions = @(
            "iam:CreatePolicy",
            "iam:PutRolePolicy",
            "iam:AttachRolePolicy",
            "iam:PassRole",
            "iam:AddUserToGroup",
            "sts:AssumeRole",
            "*"
        )

        # Function to check if a policy is dangerous based on actions
        function Is-DangerousPolicy($policyName, $entityName, $isUser) {
            $policyDocument = if ($isUser) {
                aws iam get-user-policy --user-name $entityName --policy-name $policyName --output json --profile $selectedProfile | ConvertFrom-Json
            } else {
                aws iam get-role-policy --role-name $entityName --policy-name $policyName --output json --profile $selectedProfile | ConvertFrom-Json
            }

            # Check if the policy contains any dangerous actions
            foreach ($statement in $policyDocument.PolicyDocument.Statement) {
                if ($statement.Action -contains "*" -or ($statement.Action | Where-Object { $dangerousActions -contains $_ })) {
                    return $true
                }
            }
            return $false
        }

        # Check if the user wants to fetch policies for all entities
        if ($EntityName -eq "*") {
            # Fetch all users and roles
            $users = aws iam list-users --output json --profile $selectedProfile | ConvertFrom-Json
            $roles = aws iam list-roles --output json --profile $selectedProfile | ConvertFrom-Json

            # Loop through users
            foreach ($user in $users.Users) {
                Write-Host "`nUser: $($user.UserName)" -ForegroundColor Yellow
                $userPolicies = aws iam list-user-policies --user-name $user.UserName --output json --profile $selectedProfile | ConvertFrom-Json
                foreach ($policyName in $userPolicies.PolicyNames) {
                    $isDangerous = Is-DangerousPolicy $policyName $user.UserName $true
                    if ($isDangerous) {
                        Write-Host "  Inline Policy: $($policyName) [DANGEROUS]" -ForegroundColor Red
                    } else {
                        Write-Host "  Inline Policy: $($policyName)" -ForegroundColor Green
                    }
                }
            }

            # Loop through roles
            foreach ($role in $roles.Roles) {
                Write-Host "`nRole: $($role.RoleName)" -ForegroundColor Yellow
                $rolePolicies = aws iam list-role-policies --role-name $role.RoleName --output json --profile $selectedProfile | ConvertFrom-Json
                foreach ($policyName in $rolePolicies.PolicyNames) {
                    $isDangerous = Is-DangerousPolicy $policyName $role.RoleName $false
                    if ($isDangerous) {
                        Write-Host "  Inline Policy: $($policyName) [DANGEROUS]" -ForegroundColor Red
                    } else {
                        Write-Host "  Inline Policy: $($policyName)" -ForegroundColor Green
                    }
                }
            }
        } else {
            # Specific user or role
            # Try fetching user inline policies first
            $userPolicies = aws iam list-user-policies --user-name $EntityName --output json --profile $selectedProfile | ConvertFrom-Json
            if ($userPolicies.PolicyNames.Count -gt 0) {
                Write-Host "`nUser: $EntityName" -ForegroundColor Yellow
                foreach ($policyName in $userPolicies.PolicyNames) {
                    $isDangerous = Is-DangerousPolicy $policyName $EntityName $true
                    if ($isDangerous) {
                        Write-Host "  Inline Policy: $($policyName) [DANGEROUS]" -ForegroundColor Red
                    } else {
                        Write-Host "  Inline Policy: $($policyName)" -ForegroundColor Green
                    }
                }
            } else {
                # If no user policies, try fetching role inline policies
                $rolePolicies = aws iam list-role-policies --role-name $EntityName --output json --profile $selectedProfile | ConvertFrom-Json
                if ($rolePolicies.PolicyNames.Count -gt 0) {
                    Write-Host "`nRole: $EntityName" -ForegroundColor Yellow
                    foreach ($policyName in $rolePolicies.PolicyNames) {
                        $isDangerous = Is-DangerousPolicy $policyName $EntityName $false
                        if ($isDangerous) {
                            Write-Host "  Inline Policy: $($policyName) [DANGEROUS]" -ForegroundColor Red
                        } else {
                            Write-Host "  Inline Policy: $($policyName)" -ForegroundColor Green
                        }
                    }
                } else {
                    Write-Host "`n$EntityName not found as a User or Role or does not have any inline policies." -ForegroundColor Red
                }
            }
        }
    } catch {
        Write-Host "An error occurred while enumerating inline policies: $_" -ForegroundColor Red
    }
}

# Enhanced Security Group Enumeration (Checks for misconfigurations)
function Enumerate-SecurityGroups {
    try {
        $securityGroupsJson = aws ec2 describe-security-groups --profile $selectedProfile --region $awsRegion --query "SecurityGroups[*].{ID:GroupId,Name:GroupName,Description:Description,IPPermissions:IpPermissions}" --output json
        if ($securityGroupsJson -ne '[]') {
            $securityGroups = $securityGroupsJson | ConvertFrom-Json

            Write-Host "Security Groups:" -ForegroundColor Cyan
            foreach ($group in $securityGroups) {
                Write-Host "Group Name: $($group.Name)" -ForegroundColor Cyan
                Write-Host "Group ID: $($group.ID)" -ForegroundColor Cyan
                Write-Host "Description: $($group.Description)" -ForegroundColor Cyan
                foreach ($permission in $group.IPPermissions) {
                    foreach ($ipRange in $permission.IpRanges) {
                        if ($ipRange.CidrIp -eq "0.0.0.0/0" -or $ipRange.CidrIp -eq "::/0") {
                            Write-Host "Warning: Group allows access from any IP ($($permission.FromPort)-$($permission.ToPort) to $($ipRange.CidrIp))" -ForegroundColor Red
                        }
                    }
                }
                Write-Host "---------------------------------------------" -ForegroundColor Cyan
            }
        } else {
            Write-Host "No security groups found." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "An error occurred while fetching security groups: $_" -ForegroundColor Red
    }
}

# Function to check for privilege escalation by enumerating roles with sts:AssumeRole permissions
function Check-PrivilegeEscalation {
    try {
        Write-Host "Checking for roles with sts:AssumeRole permissions..." -ForegroundColor Cyan

        # List all roles in the account with full output
        $rolesJson = aws iam list-roles --profile $selectedProfile --region $awsRegion --output json
        Write-Host "Raw roles JSON (Displaying roles with sts:AssumeRole permissions):" -ForegroundColor Green

        # Extract RoleNames (if they exist)
        $roles = ($rolesJson | ConvertFrom-Json).Roles
        if ($roles.Count -eq 0) {
            Write-Host "No IAM roles found." -ForegroundColor Yellow
        } else {
            # Define a list of full access policies
            $fullAccessPolicies = @(
                "SNSFullAccess",
                "S3FullAccess",
                "EC2FullAccess",
                "IAMFullAccess",
                "KMSFullAccess",
                "RDSFullAccess",
                "LambdaFullAccess",
                "CloudWatchFullAccess",
                "AWSSupportAccess",
                "AdministratorAccess",
                "PowerUserAccess"
            )

            foreach ($role in $roles) {
                $roleName = $role.RoleName

                # Only proceed if we have a valid RoleName
                if (-not [string]::IsNullOrWhiteSpace($roleName)) {
                    Write-Host "`n---------------------------" -ForegroundColor Cyan
                    Write-Host "Role: $roleName" -ForegroundColor Yellow
                    Write-Host "ARN: $($role.Arn)" -ForegroundColor White
                    Write-Host "Creation Date: $($role.CreateDate)" -ForegroundColor White

                    # Check the trust policy (AssumeRolePolicyDocument) for sts:AssumeRole permissions
                    $roleTrustPolicyJson = aws iam get-role --role-name $roleName --profile $selectedProfile --region $awsRegion --query "Role.AssumeRolePolicyDocument" --output json
                    $roleTrustPolicy = $roleTrustPolicyJson | ConvertFrom-Json

                    # Show trust policy details
                    Write-Host "Trust Policy (AssumeRole permissions):" -ForegroundColor Cyan
                    foreach ($statement in $roleTrustPolicy.Statement) {
                        if ($statement.Action -contains "sts:AssumeRole") {
                            Write-Host "`tPrincipal: $($statement.Principal)" -ForegroundColor Green
                            Write-Host "`tAction: $($statement.Action)" -ForegroundColor Green
                            Write-Host "`tEffect: $($statement.Effect)" -ForegroundColor Green
                        }
                    }

                    # Check if the role has attached policies
                    $attachedPolicies = aws iam list-attached-role-policies --role-name $roleName --profile $selectedProfile --region $awsRegion --query "AttachedPolicies[*].PolicyName" --output text
                    if ($attachedPolicies) {
                        Write-Host "Attached Policies:" -ForegroundColor Cyan
                        $attachedPolicies -split '\t' | ForEach-Object {
                            # Highlight full access policies
                            if ($fullAccessPolicies -contains $_) {
                                Write-Host "`tFull Access Policy: $_" -ForegroundColor Red
                            } else {
                                Write-Host "`t$_" -ForegroundColor White
                            }
                        }
                    } else {
                        Write-Host "No policies attached to this role." -ForegroundColor Yellow
                    }

                    # Check for admin-like permissions in attached policies
                    $adminLikePolicies = $attachedPolicies -split '\t' | Where-Object { $_ -match "AdministratorAccess|PowerUserAccess|FullAccess|IAMFullAccess|KMSFullAccess|SecurityAudit|AWSSupportAccess|AmazonS3FullAccess|AWSLambda_FullAccess|AmazonEC2FullAccess|AmazonRDSFullAccess" }
                    if ($adminLikePolicies) {
                        Write-Host "Warning: Role '$roleName' has admin-like permissions attached: $($adminLikePolicies -join ', ')" -ForegroundColor Red
                    }

                    # Check for privilege escalation path (assuming other roles)
                    $assumedRoles = $roleTrustPolicy.Statement | Where-Object { $_.Action -eq "sts:AssumeRole" }
                    if ($assumedRoles.Count -gt 0) {
                        Write-Host "This role allows assumption of the following roles:" -ForegroundColor Yellow
                        foreach ($assumedRole in $assumedRoles) {
                            $assumedRoleName = $assumedRole.Principal.Arn -split "/" | Select-Object -Last 1
                            Write-Host "`tAssumed Role: $assumedRoleName" -ForegroundColor Green
                            Write-Host "`tEffect: $($assumedRole.Effect)" -ForegroundColor Green
                        }
                    }

                    # Identify users with this role (SSO or user role binding)
                    $roleUsersJson = aws iam list-users --profile $selectedProfile --region $awsRegion --query "Users[?AttachedManagedPolicies[?PolicyName=='$roleName']].UserName" --output json
                    $roleUsers = $roleUsersJson | ConvertFrom-Json
                    if ($roleUsers.Count -gt 0) {
                        Write-Host "Users with this role assigned:" -ForegroundColor Cyan
                        foreach ($user in $roleUsers) {
                            Write-Host "`tUser: $($user.UserName)" -ForegroundColor Green
                        }
                    }

                    Write-Host "`n---------------------------" -ForegroundColor Cyan
                } else {
                    Write-Host "Skipping invalid role '$roleName'..." -ForegroundColor Yellow
                }
            }
        }
    } catch {
        Write-Host "An error occurred while checking privilege escalation: $_" -ForegroundColor Red
    }
}

# function to fetch policy in json format via ARN
function Get-PolicyVersionDetails {
    try {
        $policyArn = Read-Host "Enter the Policy ARN"

        # Get the list of versions
        $versions = aws iam list-policy-versions --policy-arn $policyArn --query "Versions[*].[VersionId,IsDefaultVersion]" --output text --profile $selectedProfile --region $awsRegion
        if (-not $versions) {
            Write-Host "No versions found for the specified Policy ARN: $policyArn" -ForegroundColor Red
            return
        }

        # Display available versions
        Write-Host "Available Policy Versions:" -ForegroundColor Cyan
        $versions -split "`n" | ForEach-Object {
            $fields = $_ -split '\t'
            Write-Host "  VersionId: $($fields[0]), Default: $($fields[1])" -ForegroundColor Yellow
        }

        # Ask the user to select a version
        $selectedVersion = Read-Host "Enter the VersionId you want to view (v[1/2/...])"

        # Fetch and display the policy details
        $policyDetails = aws iam get-policy-version --policy-arn $policyArn --version-id $selectedVersion --query "PolicyVersion.Document" --output json --profile $selectedProfile --region $awsRegion
        if ($policyDetails) {
            Write-Host "Policy Version $selectedVersion Details:" -ForegroundColor Cyan
            Write-Host $policyDetails | ConvertFrom-Json | ConvertTo-Json -Depth 10 | Out-String
        } else {
            Write-Host "Failed to retrieve details for VersionId $selectedVersion" -ForegroundColor Red
        }
    } catch {
        Write-Host "An error occurred. Error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Format-PolicyJson {
    try {
        Write-Host "Enter the path to your JSON file, or type 'inline' to paste JSON:" -ForegroundColor Cyan
        $inputType = Read-Host

        if ($inputType -eq "inline") {
            Write-Host "Paste your JSON below and press Enter twice to process:" -ForegroundColor Yellow
            
            # Read multiline JSON input until Enter is pressed twice
            $jsonInput = @()
            do {
                $line = Read-Host
                if ($line -ne "") {
                    $jsonInput += $line
                }
            } while ($line -ne "")

            # Combine all lines into a single string
            $jsonInput = $jsonInput -join "`n"
        } else {
            # Assume the user provided a file path
            $filePath = $inputType
            if (-Not (Test-Path $filePath)) {
                Write-Host "File not found. Please check the path and try again." -ForegroundColor Red
                return
            }

            # Read JSON from file
            $jsonInput = Get-Content $filePath -Raw
        }

        # Convert and beautify JSON
        $jsonObject = $jsonInput | ConvertFrom-Json
        $prettyJson = $jsonObject | ConvertTo-Json -Depth 100 -Compress:$false

        Write-Host "`nBeautified JSON:" -ForegroundColor Green
        Write-Output $prettyJson
    } catch {
        Write-Host "Invalid JSON input. Please check your syntax and try again." -ForegroundColor Red
    }
}

#--------------------------------------------------Complaince Check--------------------------------------------------------
# Function to check CIS AWS Foundations Benchmark compliance
function Check-CISBenchmark {
    Write-Host "Starting comprehensive CIS AWS Foundations Benchmark checks..." -ForegroundColor Cyan

    try {
        # General Configuration
        $cloudTrails = aws cloudtrail describe-trails --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
        $rootAccount = aws iam get-account-summary --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
        $buckets = aws s3api list-buckets --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
        $securityGroups = aws ec2 describe-security-groups --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
        $passwordPolicy = aws iam get-account-password-policy --output json --profile $selectedProfile --region $awsRegion 2>$null
        $vpcs = aws ec2 describe-vpcs --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
        $users = aws iam list-users --output json --profile $selectedProfile | ConvertFrom-Json
        $instances = aws ec2 describe-instances --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json

        ### CIS Section 1: Identity and Access Management ###

        # 1.1 Ensure root account MFA is enabled
        Write-Host "Checking root account MFA..." -ForegroundColor Yellow
        if ($rootAccount.SummaryMap."AccountMFAEnabled" -eq 1) {
            Write-Host "  Root account MFA is enabled." -ForegroundColor Green
        } else {
            Write-Host "  Root account MFA is NOT enabled. Enable MFA immediately." -ForegroundColor Red
        }

        # 1.2 Ensure IAM password policy requires strong parameters
        Write-Host "Checking IAM password policy..." -ForegroundColor Yellow
        if ($passwordPolicy) {
            $policy = $passwordPolicy.PasswordPolicy
            if ($policy.RequireNumbers -and $policy.RequireSymbols -and $policy.RequireUppercaseCharacters -and $policy.RequireLowercaseCharacters -and $policy.MinimumPasswordLength -ge 14 -and $policy.AllowUsersToChangePassword -and $policy.ExpirePasswords -and $policy.MaxPasswordAge -le 90 -and $policy.PasswordReusePrevention -ge 24) {
                Write-Host "  IAM password policy is compliant." -ForegroundColor Green
            } else {
                Write-Host "  IAM password policy is NOT compliant. Review and update it." -ForegroundColor Red
            }
        } else {
            Write-Host "  IAM password policy is NOT configured. Configure it immediately." -ForegroundColor Red
        }

        # 1.3 Ensure access keys are rotated every 90 days or less
        Write-Host "Checking access key rotation..." -ForegroundColor Yellow
        foreach ($user in $users.Users) {
            $accessKeys = aws iam list-access-keys --user-name $user.UserName --output json --profile $selectedProfile | ConvertFrom-Json
            foreach ($key in $accessKeys.AccessKeyMetadata) {
                $keyAge = (Get-Date) - (Get-Date $key.CreateDate)
                if ($keyAge.TotalDays -le 90) {
                    Write-Host "  Access key for $($user.UserName) is compliant." -ForegroundColor Green
                } else {
                    Write-Host "  Access key for $($user.UserName) is NOT compliant. Rotate it immediately." -ForegroundColor Red
                }
            }
        }

        # 1.4 Ensure inactive IAM users are removed
        Write-Host "Checking for inactive IAM users..." -ForegroundColor Yellow
        foreach ($user in $users.Users) {
            $lastUsed = aws iam get-user --user-name $user.UserName --output json --profile $selectedProfile | ConvertFrom-Json
            if ($lastUsed.User.PasswordLastUsed) {
                $inactiveDays = (Get-Date) - (Get-Date $lastUsed.User.PasswordLastUsed)
                if ($inactiveDays.TotalDays -gt 90) {
                    Write-Host "  IAM User $($user.UserName) is inactive for over 90 days. Consider removing them." -ForegroundColor Red
                } else {
                    Write-Host "  IAM User $($user.UserName) is active." -ForegroundColor Green
                }
            } else {
                Write-Host "  IAM User $($user.UserName) has no recent activity." -ForegroundColor Yellow
            }
        }

        ### CIS Section 2: Logging ###

        # 2.1 Ensure CloudTrail is enabled and logs are validated
        Write-Host "Checking CloudTrail configuration..." -ForegroundColor Yellow
        foreach ($trail in $cloudTrails.trailList) {
            if ($trail.IsMultiRegionTrail -and $trail.LogFileValidationEnabled) {
                Write-Host "  CloudTrail: $($trail.Name) is compliant." -ForegroundColor Green
            } else {
                Write-Host "  CloudTrail: $($trail.Name) is NOT compliant." -ForegroundColor Red
            }
        }

        # 2.2 Ensure CloudTrail logs are sent to CloudWatch Logs
        Write-Host "Checking CloudTrail integration with CloudWatch Logs..." -ForegroundColor Yellow
        foreach ($trail in $cloudTrails.trailList) {
            if ($null -ne $trail.CloudWatchLogsLogGroupArn) {
                Write-Host "  CloudTrail: $($trail.Name) logs are sent to CloudWatch." -ForegroundColor Green
            } else {
                Write-Host "  CloudTrail: $($trail.Name) logs are NOT sent to CloudWatch." -ForegroundColor Red
            }
        }

        # 2.3 Ensure S3 bucket access logging is enabled
        Write-Host "Checking S3 bucket access logging..." -ForegroundColor Yellow
        foreach ($bucket in $buckets.Buckets) {
            $loggingStatus = aws s3api get-bucket-logging --bucket $bucket.Name --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            if ($loggingStatus.LoggingEnabled) {
                Write-Host "  S3 Bucket: $($bucket.Name) has access logging enabled." -ForegroundColor Green
            } else {
                Write-Host "  S3 Bucket: $($bucket.Name) does NOT have access logging enabled." -ForegroundColor Red
            }
        }

        ### CIS Section 3: Monitoring ###

        # 3.1 Ensure a metric filter and alarm exist for unauthorized API calls
        Write-Host "Checking metric filters for unauthorized API calls..." -ForegroundColor Yellow
        # Placeholder for AWS CloudWatch metric filter and alarm checks

        # 3.2 Ensure a metric filter and alarm exist for management console sign-in without MFA
        Write-Host "Checking metric filters for console sign-in without MFA..." -ForegroundColor Yellow
        # Placeholder for metric filter and alarm checks

        ### CIS Section 4: Networking ###

        # 4.1 Ensure Security Groups do not allow unrestricted ingress
        Write-Host "Checking Security Groups for unrestricted ingress..." -ForegroundColor Yellow
        foreach ($group in $securityGroups.SecurityGroups) {
            foreach ($permission in $group.IpPermissions) {
                foreach ($range in $permission.IpRanges) {
                    if ($range.CidrIp -eq "0.0.0.0/0") {
                        Write-Host "  Security Group: $($group.GroupName) allows unrestricted ingress (0.0.0.0/0)." -ForegroundColor Red
                    }
                }
            }
        }

        # 4.2 Ensure no security groups allow unrestricted ingress to port 22
        Write-Host "Checking Security Groups for unrestricted SSH access (port 22)..." -ForegroundColor Yellow
        foreach ($group in $securityGroups.SecurityGroups) {
            foreach ($permission in $group.IpPermissions) {
                if ($permission.FromPort -eq 22 -and $permission.ToPort -eq 22) {
                    foreach ($range in $permission.IpRanges) {
                        if ($range.CidrIp -eq "0.0.0.0/0") {
                            Write-Host "  Security Group: $($group.GroupName) allows unrestricted SSH access (0.0.0.0/0)." -ForegroundColor Red
                        }
                    }
                }
            }
        }

        # 4.3 Ensure the default security group of every VPC restricts all traffic
        Write-Host "Checking default Security Groups for open traffic..." -ForegroundColor Yellow
        foreach ($vpc in $vpcs.Vpcs) {
            $defaultSecurityGroups = aws ec2 describe-security-groups --filters Name=vpc-id,Values=$vpc.VpcId Name=group-name,Values=default --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            foreach ($group in $defaultSecurityGroups.SecurityGroups) {
                if ($group.IpPermissions.Count -gt 0 -or $group.IpPermissionsEgress.Count -gt 0) {
                    Write-Host "  Default Security Group for VPC $($vpc.VpcId) allows traffic. Restrict all rules." -ForegroundColor Red
                } else {
                    Write-Host "  Default Security Group for VPC $($vpc.VpcId) is compliant." -ForegroundColor Green
                }
            }
        }

        ### CIS Section 5: Monitoring and Logging ###

        # 5.1 Ensure AWS Config is enabled in all regions
        Write-Host "Checking AWS Config status in all regions..." -ForegroundColor Yellow
        $allRegions = aws ec2 describe-regions --output json | ConvertFrom-Json
        foreach ($region in $allRegions.Regions.RegionName) {
            $configStatus = aws configservice describe-configuration-recorder-status --region $region --output json --profile $selectedProfile | ConvertFrom-Json
            if ($configStatus.ConfigurationRecordersStatus.Count -eq 0 -or !$configStatus.ConfigurationRecordersStatus[0].Recording) {
                Write-Host "  AWS Config is NOT enabled in region $region." -ForegroundColor Red
            } else {
                Write-Host "  AWS Config is enabled in region $region." -ForegroundColor Green
            }
        }

        # 5.2 Ensure S3 buckets for CloudTrail logs are not publicly accessible
        Write-Host "Checking CloudTrail log bucket permissions..." -ForegroundColor Yellow
        foreach ($trail in $cloudTrails.trailList) {
            if ($trail.S3BucketName) {
                $bucketAcl = aws s3api get-bucket-acl --bucket $trail.S3BucketName --output json --profile $selectedProfile | ConvertFrom-Json
                foreach ($grant in $bucketAcl.Grants) {
                    if ($grant.Grantee.URI -eq "http://acs.amazonaws.com/groups/global/AllUsers" -or $grant.Grantee.URI -eq "http://acs.amazonaws.com/groups/global/AuthenticatedUsers") {
                        Write-Host "  CloudTrail log bucket $($trail.S3BucketName) is publicly accessible. Restrict access." -ForegroundColor Red
                    } else {
                        Write-Host "  CloudTrail log bucket $($trail.S3BucketName) is compliant." -ForegroundColor Green
                    }
                }
            }
        }

        # 5.3 Ensure VPC flow logging is enabled in all VPCs
        Write-Host "Checking VPC Flow Logs..." -ForegroundColor Yellow
        foreach ($vpc in $vpcs.Vpcs) {
            $flowLogs = aws ec2 describe-flow-logs --filter Name=resource-id,Values=$vpc.VpcId --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            if ($flowLogs.FlowLogs.Count -eq 0) {
                Write-Host "  VPC $($vpc.VpcId) does NOT have flow logs enabled. Enable them." -ForegroundColor Red
            } else {
                Write-Host "  VPC $($vpc.VpcId) has flow logs enabled." -ForegroundColor Green
            }
        }

        ### CIS Section 6: Other Recommendations ###

        # 6.1 Ensure all IAM users have MFA enabled
        Write-Host "Checking MFA status for all IAM users..." -ForegroundColor Yellow
        foreach ($user in $users.Users) {
            $mfaDevices = aws iam list-mfa-devices --user-name $user.UserName --output json --profile $selectedProfile | ConvertFrom-Json
            if ($mfaDevices.MFADevices.Count -eq 0) {
                Write-Host "  IAM User $($user.UserName) does NOT have MFA enabled." -ForegroundColor Red
            } else {
                Write-Host "  IAM User $($user.UserName) has MFA enabled." -ForegroundColor Green
            }
        }

        # 6.2 Ensure all EC2 instances have detailed monitoring enabled
        Write-Host "Checking EC2 instance monitoring..." -ForegroundColor Yellow
        foreach ($reservation in $instances.Reservations) {
            foreach ($instance in $reservation.Instances) {
                if ($instance.Monitoring.State -ne "enabled") {
                    Write-Host "  EC2 Instance $($instance.InstanceId) does NOT have detailed monitoring enabled." -ForegroundColor Red
                } else {
                    Write-Host "  EC2 Instance $($instance.InstanceId) has detailed monitoring enabled." -ForegroundColor Green
                }
            }
        }

        Write-Host "CIS AWS Foundations Benchmark checks completed." -ForegroundColor Cyan

    } catch {
        Write-Host "Error while checking CIS Benchmark: $_" -ForegroundColor Red
    }
}

#--------------------------------------------------Complaince Check--------------------------------------------------------

# Function to analyze unused IAM permissions
function Analyze-UnusedIAMPermissions {
    Write-Host "Starting analysis of unused IAM permissions..." -ForegroundColor Cyan

    try {
        # Fetch list of IAM users
        Write-Host "Fetching IAM users..." -ForegroundColor Yellow
        $users = aws iam list-users --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json

        foreach ($user in $users.Users) {
            Write-Host "Analyzing permissions for user: $($user.UserName)" -ForegroundColor Green

            # Fetch Access Advisor data for the user
            $accessAdvisor = aws iam generate-service-last-accessed-details --arn $user.Arn --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            $jobId = $accessAdvisor.JobId

            # Wait for the job to complete
            Write-Host "Waiting for access advisor job to complete..." -ForegroundColor Yellow
            Start-Sleep -Seconds 5

            $jobStatus = aws iam get-service-last-accessed-details --job-id $jobId --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            while ($jobStatus.JobStatus -ne "COMPLETED") {
                Write-Host "Job Status: $($jobStatus.JobStatus)" -ForegroundColor Yellow
                Start-Sleep -Seconds 5
                $jobStatus = aws iam get-service-last-accessed-details --job-id $jobId --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            }

            # Parse results to find unused services
            foreach ($service in $jobStatus.ServicesLastAccessed) {
                if (-not $service.LastAuthenticated) {
                    Write-Host "  Unused Permission: $($service.ServiceName) (No access detected)" -ForegroundColor Red
                }
            }
        }

    } catch {
        Write-Host "Error during unused IAM permissions analysis: $_" -ForegroundColor Red
    }
}

# Function to enumerate VPCs and highlight potential security flaws
function Enumerate-VPCs {
    Write-Host "Starting VPC enumeration and security analysis..." -ForegroundColor Cyan

    try {
        # Fetch list of VPCs
        Write-Host "Fetching VPCs..." -ForegroundColor Yellow
        $vpcs = aws ec2 describe-vpcs --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json

        foreach ($vpc in $vpcs.Vpcs) {
            Write-Host "Analyzing VPC: $($vpc.VpcId)" -ForegroundColor Green

            # Check if the VPC is publicly accessible (has an internet gateway attached)
            $igws = aws ec2 describe-internet-gateways --filters Name=attachment.vpc-id,Values=$($vpc.VpcId) --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            if ($igws.InternetGateways.Count -gt 0) {
                Write-Host "  Potential Flaw: VPC $($vpc.VpcId) has an Internet Gateway attached." -ForegroundColor Red
            } else {
                Write-Host "  VPC $($vpc.VpcId) does not have an Internet Gateway." -ForegroundColor Cyan
            }

            # Enumerate security groups and check for overly permissive rules
            $securityGroups = aws ec2 describe-security-groups --filters Name=vpc-id,Values=$($vpc.VpcId) --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            foreach ($sg in $securityGroups.SecurityGroups) {
                Write-Host "  Analyzing Security Group: $($sg.GroupId) - $($sg.GroupName)" -ForegroundColor Yellow

                foreach ($permission in $sg.IpPermissions) {
                    if ($permission.IpRanges | Where-Object { $_.CidrIp -eq "0.0.0.0/0" }) {
                        Write-Host "    Potential Flaw: Security Group $($sg.GroupId) allows ingress from 0.0.0.0/0 on port $($permission.FromPort)-$($permission.ToPort)." -ForegroundColor Red
                    }
                }
                foreach ($permission in $sg.IpPermissionsEgress) {
                    if ($permission.IpRanges | Where-Object { $_.CidrIp -eq "0.0.0.0/0" }) {
                        Write-Host "    Potential Flaw: Security Group $($sg.GroupId) allows egress to 0.0.0.0/0 on port $($permission.FromPort)-$($permission.ToPort)." -ForegroundColor Red
                    }
                }
            }

            # Check for unused network ACLs (NACLs)
            $nacls = aws ec2 describe-network-acls --filters Name=vpc-id,Values=$($vpc.VpcId) --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            foreach ($nacl in $nacls.NetworkAcls) {
                if ($nacl.Associations.Count -eq 0) {
                    Write-Host "  Potential Flaw: Network ACL $($nacl.NetworkAclId) is not associated with any subnet." -ForegroundColor Red
                }

                # Check for overly permissive NACL rules
                foreach ($entry in $nacl.Entries) {
                    if ($entry.CidrBlock -eq "0.0.0.0/0" -and $entry.RuleAction -eq "allow") {
                        Write-Host "    Potential Flaw: Network ACL $($nacl.NetworkAclId) allows $($entry.RuleAction) traffic from 0.0.0.0/0 on port $($entry.PortRange)." -ForegroundColor Red
                    }
                }
            }

            # Check route tables for public routes
            $routeTables = aws ec2 describe-route-tables --filters Name=vpc-id,Values=$($vpc.VpcId) --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            foreach ($routeTable in $routeTables.RouteTables) {
                foreach ($route in $routeTable.Routes) {
                    if ($route.GatewayId -like "igw-*") {
                        Write-Host "  Potential Flaw: Route Table $($routeTable.RouteTableId) has a public route via Internet Gateway $($route.GatewayId)." -ForegroundColor Red
                    }
                }
            }

            # Check subnets for public accessibility
            $subnets = aws ec2 describe-subnets --filters Name=vpc-id,Values=$($vpc.VpcId) --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            foreach ($subnet in $subnets.Subnets) {
                if ($subnet.MapPublicIpOnLaunch) {
                    Write-Host "  Potential Flaw: Subnet $($subnet.SubnetId) is configured to assign public IPs on launch." -ForegroundColor Red
                }
            }
        }
    } catch {
        Write-Host "Error during VPC enumeration: $_" -ForegroundColor Red
    }
}

# Function to perform advanced S3 enumeration
function Check-S3BucketSecurity {
    Write-Host "Starting advanced S3 bucket security checks..." -ForegroundColor Cyan

    # List all S3 buckets
    $buckets = aws s3api list-buckets --query "Buckets[*].Name" --output text --profile $selectedProfile --region $awsRegion
    if (-not $buckets) {
        Write-Host "No S3 buckets found." -ForegroundColor Yellow
        return
    }

    foreach ($bucket in $buckets -split "`t") {
        Write-Host "------------------------------------------------" -ForegroundColor Green
        Write-Host "Checking bucket: $bucket..." -ForegroundColor Cyan

        # Check bucket ACL to determine permissions
        try {
            $acl = aws s3api get-bucket-acl --bucket $bucket --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            Write-Host "  Bucket ACLs and Permissions:" -ForegroundColor Yellow
            $acl.Grants | ForEach-Object {
                Write-Host "    Grantee: $($_.Grantee.DisplayName), Permission: $($_.Permission)"
            }
        } catch {
            Write-Host "  Unable to fetch ACL for bucket: $bucket. Error: $_" -ForegroundColor Red
        }

        # Check if the bucket has public access
        try {
            $publicAccessBlock = aws s3api get-bucket-policy-status --bucket $bucket --profile $selectedProfile --region $awsRegion
            if ($publicAccessBlock.PolicyStatus.Status -eq "Public") {
                Write-Host "  Bucket is publicly accessible!" -ForegroundColor Red
            } else {
                Write-Host "  Bucket is not publicly accessible." -ForegroundColor Green
            }
        } catch {
            Write-Host "  Unable to check bucket's public access: $_" -ForegroundColor Red
        }

        # Check the bucket's versioning status
        try {
            $versioning = aws s3api get-bucket-versioning --bucket $bucket --output json --profile $selectedProfile --region $awsRegion
            if ($versioning.Status -eq "Enabled") {
                Write-Host "  Versioning is enabled for the bucket." -ForegroundColor Green
            } else {
                Write-Host "  Versioning is not enabled for the bucket." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  Unable to check versioning for bucket: $bucket. Error: $_" -ForegroundColor Red
        }

        # Check if the bucket has server-side encryption enabled
        try {
            $encryption = aws s3api get-bucket-encryption --bucket $bucket --output json --profile $selectedProfile --region $awsRegion
            if ($encryption.ServerSideEncryptionConfiguration) {
                Write-Host "  Bucket has server-side encryption enabled." -ForegroundColor Green
            } else {
                Write-Host "  Bucket does not have encryption enabled." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  Unable to check encryption for bucket: $bucket. Error: $_" -ForegroundColor Red
        }

        # Check the bucket policy
        try {
            $policy = aws s3api get-bucket-policy --bucket $bucket --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            Write-Host "  Bucket policy: $($policy.Policy)" -ForegroundColor Green
        } catch {
            Write-Host "  Unable to fetch bucket policy for: $bucket. Error: $_" -ForegroundColor Yellow
        }

        # List objects in the bucket and check access to them
        try {
            $objects = aws s3api list-objects --bucket $bucket --query "Contents[*].{Key:Key,Size:Size}" --output json --profile $selectedProfile --region $awsRegion | ConvertFrom-Json
            if (-not $objects) {
                Write-Host "  Bucket is empty or inaccessible." -ForegroundColor Yellow
                continue
            }

            $deniedCount = 0  # Track denied files
            $totalFiles = $objects.Count  # Track total files
            $deniedFiles = @()  # List to track denied files

            foreach ($object in $objects) {
                $objectKey = $object.Key

                # Check the object permissions
                try {
                    # Attempt to get object metadata (head-object) to check permissions
                    $response = aws s3api head-object --bucket $bucket --key $objectKey --profile $selectedProfile --region $awsRegion 2>&1
                    if ($response -match "403") {
                        $deniedCount++
                        $deniedFiles += $objectKey
                        Write-Host "    [DENIED] Download access denied for object: $objectKey (403 Forbidden)" -ForegroundColor Red
                    } else {
                        Write-Host "    [ALLOWED] Download access confirmed for object: $objectKey." -ForegroundColor Green
                    }

                    # Ask the user to skip the file checking process after every 20 denied files
                    if ($deniedCount % 5 -eq 0 -and $deniedCount -gt 0) {
                        $skipBucket = Read-Host "5 files with denied access found. Do you want to skip checking files for this bucket entirely? (Press 's' to skip, Press Enter to continue)"
                        if ($skipBucket -eq "s") {
                            Write-Host "Skipping checking files for bucket: $bucket" -ForegroundColor Yellow
                            break  # Skip to next bucket
                        }
                    }
                } catch {
                    Write-Host "    [ERROR] Error accessing object: $objectKey. Error: $_" -ForegroundColor Yellow
                }
            }

            # Show denied file count if there are any denied downloads
            if ($deniedCount -gt 0) {
                Write-Host "    $deniedCount/$totalFiles file(s) download denied in bucket: $bucket" -ForegroundColor Yellow
                Write-Host "    Denied files: $($deniedFiles -join ', ')" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  Unable to fetch objects for bucket: $bucket. Error: $_" -ForegroundColor Red
        }

        Write-Host "------------------------------------------------" -ForegroundColor Green
    }
}

# Function to check rotational keys
function Check-RotationalKeys {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IAMEntityName
    )

    # Check if the AWS CLI is installed
    if (-not (Get-Command "aws" -ErrorAction SilentlyContinue)) {
        Write-Host "AWS CLI is not installed or not in the system PATH. Please install or configure it before proceeding." -ForegroundColor Red
        return
    }

    if ($IAMEntityName -eq "*") {
        # Fetch all IAM users
        $users = aws iam list-users --query "Users[*].UserName" --output text --profile $selectedProfile
        if (-not $users) {
            Write-Host "No IAM users found." -ForegroundColor Yellow
            return
        }

        Write-Host "Checking access key rotation for all users..." -ForegroundColor Cyan
        foreach ($user in $users -split "`t") {
            Check-UserKeys $user
        }
    } else {
        # Check for a specific user
        Write-Host "Checking access key rotation for user: $IAMEntityName" -ForegroundColor Cyan
        Check-UserKeys $IAMEntityName
    }
}

# Function to check rotational keys_2
function Check-UserKeys {
    param (
        [string]$UserName
    )

    # Fetch the access keys for the user
    $keys = aws iam list-access-keys --user-name $UserName --query "AccessKeyMetadata[*].{KeyId:AccessKeyId,CreatedDate:CreateDate,Status:Status}" --output json --profile $selectedProfile
    if (-not $keys) {
        Write-Host "No access keys found for user: $UserName" -ForegroundColor Yellow
        return
    }

    # Convert JSON output to a PowerShell object
    $keys = $keys | ConvertFrom-Json
    foreach ($key in $keys) {
        $keyAge = (Get-Date) - [datetime]$key.CreatedDate
        Write-Host "User: $UserName, Key: $($key.KeyId), Created: $($key.CreatedDate), Age: $($keyAge.Days) days" -ForegroundColor White
        
        # Check if the key is inactive
        if ($key.Status -eq "Inactive") {
            Write-Host "Key $($key.KeyId) for user $UserName is inactive. Please review the key status." -ForegroundColor Red
        }

        # Age-based rotation check
        if ($keyAge.Days -gt 90) {
            Write-Host "Key $($key.KeyId) for user $UserName is older than 90 days. Consider rotating." -ForegroundColor Yellow
        } else {
            Write-Host "Key $($key.KeyId) for user $UserName is within the rotation policy." -ForegroundColor Green
        }
    }
}

# function for checking sensitive ports
function Check-SensitivePorts {
    param (
        [string]$selectedProfile,
        [string]$awsRegion,
        [switch]$Verbose
    )

    # Define a list of potentially sensitive ports to check
    $sensitivePorts = @(22, 23, 3389, 21, 3306, 5432, 6379, 27017)

    try {
        # Validate inputs
        if (-not $awsRegion) {
            Write-Host "AWS region is not specified. Please provide a valid AWS region." -ForegroundColor Red
            return
        }
        if (-not $selectedProfile) {
            Write-Host "AWS CLI profile is not specified. Please provide a valid AWS CLI profile." -ForegroundColor Red
            return
        }

        # Fetch all EC2 instances in the region
        if ($Verbose) {
            Write-Host "Fetching EC2 instances in region '$awsRegion' for profile '$selectedProfile'..." -ForegroundColor Yellow
        }
        $instances = aws ec2 describe-instances --profile $selectedProfile --region $awsRegion --query "Reservations[].Instances[].[InstanceId, Tags[?Key=='Name']|[0].Value, SecurityGroups[].GroupId, State.Name]" --output json | ConvertFrom-Json

        if (-not $instances) {
            Write-Host "No EC2 instances found in region $awsRegion." -ForegroundColor Yellow
            return
        }

        # Initialize result arrays
        $instancesWithSensitivePorts = @()
        $instancesWithoutSensitivePorts = @()

        # Process each instance
        foreach ($instance in $instances) {
            $instanceId = $instance[0]
            $instanceName = if ($instance[1]) { $instance[1] } else { "No Name" }
            $securityGroups = $instance[2]
            $instanceState = $instance[3]

            if ($Verbose) {
                Write-Host "Checking instance $instanceId ($instanceName)... State: $instanceState" -ForegroundColor Cyan
            }

            $foundSensitivePort = $false
            $openPorts = @()

            # Check each security group for sensitive ports
            foreach ($sg in $securityGroups) {
                $sgDetails = aws ec2 describe-security-groups --group-ids $sg --profile $selectedProfile --region $awsRegion --query "SecurityGroups[0].IpPermissions" --output json | ConvertFrom-Json

                foreach ($permission in $sgDetails) {
                    $fromPort = $permission.FromPort
                    $toPort = $permission.ToPort

                    if ($fromPort -and $toPort) {
                        foreach ($port in $sensitivePorts) {
                            if ($port -ge $fromPort -and $port -le $toPort) {
                                if ($Verbose) {
                                    Write-Host "Sensitive port $port found in security group $sg for instance $instanceId ($instanceName)." -ForegroundColor Red
                                }
                                $foundSensitivePort = $true
                                $openPorts += $port
                            }
                        }
                    }
                }
            }

            # Add to results based on findings
            if ($foundSensitivePort) {
                $instancesWithSensitivePorts += [PSCustomObject]@{
                    InstanceId    = $instanceId
                    InstanceName  = $instanceName
                    PortsEnabled  = $openPorts -join ', '
                    InstanceState = $instanceState
                }
            } else {
                $instancesWithoutSensitivePorts += [PSCustomObject]@{
                    InstanceId    = $instanceId
                    InstanceName  = $instanceName
                    PortsEnabled  = "None"
                    InstanceState = $instanceState
                }
            }
        }

        # Display results
        Write-Host "`nInstances with Sensitive Ports Enabled:" -ForegroundColor Red
        $instancesWithSensitivePorts | Format-Table -Property InstanceId, InstanceName, PortsEnabled, InstanceState

        Write-Host "`nInstances without Sensitive Ports Enabled:" -ForegroundColor Green
        $instancesWithoutSensitivePorts | Format-Table -Property InstanceId, InstanceName, PortsEnabled, InstanceState

        Write-Host "`nSummary:" -ForegroundColor Cyan
        Write-Host "Total Instances with Sensitive Ports: $($instancesWithSensitivePorts.Count)" -ForegroundColor Red
        Write-Host "Total Instances without Sensitive Ports: $($instancesWithoutSensitivePorts.Count)" -ForegroundColor Green

    } catch {
        Write-Host "An error occurred: $($_.Exception.Message)" -ForegroundColor Red
    }
}
