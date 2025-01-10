# AWS-Automation-Toolkit

A comprehensive PowerShell-based AWS automation toolkit to simplify and enhance AWS management tasks. The toolkit includes scripts for identity verification, user enumeration, security checks, IAM policy analysis, and more. Designed for developers, security analysts, and cloud engineers.

## Overview

The **AWS Automation Toolkit** is a collection of PowerShell scripts designed to automate and simplify AWS management tasks. It includes functionalities for identity verification, user enumeration, security assessments, policy analysis, and compliance checks. With an intuitive interface and modular functions, the toolkit helps streamline routine AWS operations.

---

## Features

### Main Menu Options

1. **Check AWS Identity (WhoAmI)**: Identify the currently authenticated AWS identity.
2. **Users Enumeration, Last Login, MFA Status**: List all users, their last login timestamps, and MFA configuration.
3. **Lambda Security Check**: Analyze AWS Lambda configurations for security issues.
4. **Check for Publicly Accessible S3 Buckets**: Identify misconfigured S3 buckets with public access.
5. **IAM User/Role Managed Policy Enumeration**: List and evaluate all managed policies attached to users and roles.
6. **IAM User/Role Inline Policy Enumeration**: Inspect inline policies attached to users and roles.
7. **Enumerate Security Groups**: Analyze security group configurations for open or overly permissive rules.
8. **Privilege Escalation Check**: Detect potential privilege escalation paths in IAM configurations.
9. **Policy Details via ARN**: Retrieve detailed information about a policy using its ARN.
10. **JSON Beautifier**: Format and beautify JSON outputs for better readability.
11. **CIS Benchmark Compliance Check**: Evaluate your AWS environment against CIS benchmarks.
12. **Advanced S3 Enumeration**: Deep dive into S3 configurations for enhanced security insights.
13. **Analyze Unused IAM Permissions**: Identify unused IAM permissions for potential cleanup.
14. **VPCs Enumeration & Weaknesses Check**: Enumerate VPC configurations and identify weaknesses.
15. **Check Rotational Keys**: Verify compliance with key rotation policies.
16. **Check for Sensitive Open Ports on Instances**: Analyze instances for open ports that might pose security risks.
17. **Check for EC2 Instances with Outdated AMIs**: Identify EC2 instances running outdated AMIs.
18. **Check for Unencrypted EBS Volumes**: Check for unencrypted EBS volumes in the environment.
19. **Inspect API Gateway Configurations**: Inspect the configurations of API Gateway for security misconfigurations.
20. **List Unused Security Groups**: List security groups that are not being used.
21. **Exit**: Exit the toolkit.

---

## Prerequisites

- **AWS CLI**: Installed and configured on your system.
- **PowerShell**: Version 5.0 or higher.
- **AWS Profiles**: Configured in `~/.aws/credentials`.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/AWS-Automation-Toolkit.git
   cd AWS-Automation-Toolkit
   ```

2. Ensure all scripts (`ComprehensiveAWS_testing.ps1` and `Functions.ps1`) are in the same directory.

---

## Usage

1. Navigate to the directory containing the scripts:
   ```powershell
   cd '.\AWS Automation Toolkit\'
   ```

2. Execute the main script:
   ```powershell
   .\ComprehensiveAWS_testing.ps1
   ```

3. If you encounter an execution policy error, run:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

4. Follow the on-screen menu prompts to select and execute desired operations.

---

## Example Workflow

### Selecting an AWS Profile and Region
1. The script will prompt you to select an AWS profile from those configured in your system:
   ```
   Available AWS Profiles:
   1. default
   2. work
   Select a profile by entering the corresponding number: 2
   Selected profile: work
   ```
2. Then, enter the AWS region:
   ```
   Enter AWS Region (default: ap-south-1): us-west-2
   Using AWS Region: us-west-2
   ```

### Running a Feature (e.g., Checking AWS Identity)
Select an option from the main menu:
```
Main Dashboard - Select an Option:
1. Check AWS Identity (WhoAmI)
...
Enter the number of your choice: 1
```
The script will display the authenticated AWS identity:
```
AWS Identity Information:
UserId: AIDXXXXXXXXXXXXXX
Account: 123456789012
Arn: arn:aws:iam::123456789012:user/username
```

---

## Contributions

Contributions, issues, and feature requests are welcome! Fork the repository, make changes, and submit a pull request.

---

For questions or support, please contact [[divytej](https://in.linkedin.com/in/divytej)].
