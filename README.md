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
13. **Analyze Unused IAM Permissions**: Analyze unused IAM permissions for weaknesses.
14. **VPCs Enumeration & Weaknesses Check**: Assess logging and monitoring configurations for potential issues.
15. **Check Rotational Keys**: Verify compliance with key rotation policies.
16. **Check for sensitive open ports on instance**: Check for open ports on instance

---

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/AWS-Automation-Toolkit.git
   cd AWS-Automation-Toolkit
   ```

## Usage
1. Navigate to the directory:
   ```powershell
   cd '.\AWS Automation Toolkit\'
   ```
2. Execute the main script:
   ```powershell
   .\ComprehensiveAWS_testing.ps1
   ```
   If faced with any issue, try:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. Follow the menu prompts to select the desired option.
