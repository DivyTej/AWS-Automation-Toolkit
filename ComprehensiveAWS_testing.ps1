# Dot-source the Functions.ps1 file
. "$PSScriptRoot\Functions.ps1"  # Ensure Functions.ps1 is in the same directory as this script

# Function to select an AWS profile
function Select-AWSProfile {
    $profiles = Select-String -Path "$env:USERPROFILE\.aws\credentials" -Pattern '^\[.*\]' | ForEach-Object {
        $_.Line.Trim('[', ']')
    }

    if (-not $profiles) {
        Write-Host "No AWS profiles found. Please configure AWS profiles first." -ForegroundColor Yellow
        exit
    }

    Write-Host "Available AWS Profiles:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $profiles.Count; $i++) {
        Write-Host "$($i + 1). $($profiles[$i])" -ForegroundColor Yellow
    }

    do {
        $selectedIndex = Read-Host "Enter the number corresponding to the profile you want to use"
        if ($selectedIndex -match '^\d+$') {
            $selectedIndex = [int]$selectedIndex
            if ($selectedIndex -ge 1 -and $selectedIndex -le $profiles.Count) {
                return $profiles[$selectedIndex - 1]
            }
        }
        Write-Host "Invalid selection. Please try again." -ForegroundColor Red
    } while ($true)
}

# Function to select an AWS region
function Select-AWSRegion {
    $awsRegion = Read-Host "Enter AWS Region (default: ap-south-1)"
    if (-not $awsRegion) {
        $awsRegion = "ap-south-1"
        Write-Host "Default region set to $awsRegion" -ForegroundColor Green
    }
    return $awsRegion
}

# Function to display the main menu
function Show-MainMenu {
    $menuOptions = @(
        "1. Check AWS Identity (WhoAmI)",
        "2. Users Enumeration, Last Login, MFA Status",
        "3. Lambda Security Check",
        "4. Check for Publicly Accessible S3 Buckets in each & every region",
        "5. IAM User/Role Managed Policy Enumeration",
        "6. IAM User/Role Inline Policy Enumeration",
        "7. Enumerate Security Groups",
        "8. Privilege Escalation Check",
        "9. Policy Details via ARN",
        "10. JSON Beautifier",
        "11. CIS Benchmark Compliance Check",
        "12. Advanced S3 Enumeration",
        "13. Analyze Unused IAM Permissions",
        "14. VPCs Enumeration & Weaknesses Check",
        "15. Check Rotational Keys",
        "16. Check for sensitive open ports on instance",
        "17. Check for EC2 Instances with Outdated AMIs",
        "18. Check for Unencrypted EBS Volumes",
        "19. Inspect API Gateway Configurations",
        "20. List Unused Security Groups",
        "21. List AWS Logging",
        "22. List all RDS instances with details",
        "23. Check SQS Misconfiguration",
        "24. Exit"
    )
    Write-Host "`nMain Dashboard - Select an Option:" -ForegroundColor Cyan
    $menuOptions | ForEach-Object { Write-Host $_ }
    return (Read-Host "Enter the number of your choice")
}

# Function to wait for user confirmation
function Wait-ForConfirmation {
    Read-Host "Press Enter to return to the main dashboard"
}

# Function to list all RDS instances and details using AWS CLI
function List-RDSInstances {
    param (
        [string]$selectedProfile,
        [string]$awsRegion
    )

    Write-Host "Listing RDS instances in region: $awsRegion" -ForegroundColor Cyan

    try {
        $rdsInstances = aws rds describe-db-instances --profile $selectedProfile --region $awsRegion --query "DBInstances[*].[DBInstanceIdentifier,Engine,EngineVersion,PubliclyAccessible,KmsKeyId,DeletionProtection,AssociatedRoles]" --output table

        if ($rdsInstances) {
            Write-Host "`nRDS Instances:" -ForegroundColor Green
            Write-Host $rdsInstances
        } else {
            Write-Host "No RDS instances found." -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Error retrieving RDS instances: $_" -ForegroundColor Red
    }
}

# Main script logic
Write-Host "AWS IAM Management Tool" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# Profile and region selection
$selectedProfile = Select-AWSProfile
Write-Host "You have selected profile: $selectedProfile" -ForegroundColor Green
$awsRegion = Select-AWSRegion
Write-Host "Using AWS Region: $awsRegion" -ForegroundColor Green  # Debugging region

# Main loop
do {
    $functionChoice = Show-MainMenu

    switch ($functionChoice) {
        "1" { Check-Identity }
        "2" { Check-IAMUsers }
        "3" { Check-LambdaSecurity }
        "4" { Check-PublicS3Buckets }
        "5" {
            $EntityName = Read-Host "Enter IAM User or Role name for Managed Policies enumeration (Enter * for all)"
            Enumerate-ManagedPolicies -EntityName $EntityName
        }
        "6" {
            $EntityName = Read-Host "Enter IAM User, Role, or Group name for Inline Policies enumeration (Enter * for all)"
            Enumerate-InlinePolicies -EntityName $EntityName
        }
        "7" { Enumerate-SecurityGroups }
        "8" { Check-PrivilegeEscalation }
        "9" { Get-PolicyVersionDetails }
        "10" {
            $jsonInput = Read-Host "Enter the JSON string to beautify"
            if (-not [string]::IsNullOrWhiteSpace($jsonInput)) {
                Format-PolicyJson -JsonString $jsonInput
            } else {
                Write-Host "No JSON input provided. Returning to dashboard..." -ForegroundColor Yellow
            }
        }
        "11" { Check-CISBenchmark }
        "12" { Check-S3BucketSecurity }
        "13" { Analyze-UnusedIAMPermissions }
        "14" { Enumerate-VPCs }
        "15" {
            $IAMEntityName = Read-Host "Enter IAM username or '*' to check all users"
            Check-RotationalKeys -IAMEntityName $IAMEntityName
        }
        "16" { Check-SensitivePorts -selectedProfile $selectedProfile -awsRegion $awsRegion -Verbose }
        "17" { Check-EC2OutdatedAMIs -selectedProfile $selectedProfile -awsRegion $awsRegion }
        "18" { Check-UnencryptedEBSVolumes -selectedProfile $selectedProfile -awsRegion $awsRegion }
        "19" { 
            Write-Host "Inspecting API Gateway Configurations in region: $awsRegion" -ForegroundColor Green
            Inspect-APIGatewayConfigurations -Region $awsRegion -SelectedProfile $selectedProfile 
        }
        "20" { 
            Check-SecurityGroups -SelectedProfile $selectedProfile -awsRegion $awsRegion -Verbose
        }
        "21" { 
            Check-AWSLoggingStatus -SelectedProfile $selectedProfile -awsRegion $awsRegion -Verbose
        }
        "22" {
            Get-RDSInstances -SelectedProfile $selectedProfile -awsRegion $awsRegion -Verbose
        }
        "23" { Get-SQSConfiguration -SelectedProfile $selectedProfile -awsRegion $awsRegion -Verbose }
        "24" {
            Write-Host "Exiting script..." -ForegroundColor Green
            return  # Exit the loop and script
        }
        default {
            Write-Host "Invalid choice. Please enter a number between 1 and 24." -ForegroundColor Red
        }
    }

    Wait-ForConfirmation
} while ($true)
