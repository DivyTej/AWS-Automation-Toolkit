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
	"16. Check for sensitive ports",
        "17. Exit"
    )
    Write-Host "`nMain Dashboard - Select an Option:" -ForegroundColor Cyan
    $menuOptions | ForEach-Object { Write-Host $_ }
    return (Read-Host "Enter the number of your choice")
}

# Function to wait for user confirmation
function Wait-ForConfirmation {
    Read-Host "Press Enter to return to the main dashboard"
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
        "3" { Check-LambdaSecurity }  # Call the Lambda Security Check function
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
        "16" { 
            Check-SensitivePorts -selectedProfile $selectedProfile -awsRegion $awsRegion -Verbose
        }
	"17" {
	    Write-Host "Exiting script..." -ForegroundColor Green
	    return  # This will exit the entire script
        }
        default {
            Write-Host "Invalid choice. Please enter a number between 1 and 16." -ForegroundColor Red
        }
    }

    Wait-ForConfirmation
} while ($true)
