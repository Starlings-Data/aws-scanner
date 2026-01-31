#!/bin/bash
#
# Starlings AWS Security Scanner v1.0
# ====================================
# 
# This script runs locally in YOUR environment.
# Your AWS credentials NEVER leave your machine.
#
# What it does:
#   - Runs read-only checks against your AWS account
#   - Identifies security misconfigurations
#   - Outputs a JSON report you can review before sharing
#
# Requirements:
#   - AWS CLI installed and configured
#   - Read-only permissions (see scan-policy.json for minimal IAM policy)
#
# Usage:
#   ./starlings-aws-scan.sh [--region REGION] [--output FILE]
#
# Source: https://github.com/Starlings-Data/aws-scanner
# License: MIT
#

set -e

# ============================================================================
# Configuration
# ============================================================================

SCANNER_VERSION="1.0.0"
DEFAULT_OUTPUT="aws-security-report.json"
REGION=""
OUTPUT_FILE=""

# Colors for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# Helper Functions
# ============================================================================

print_banner() {
    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}     🛡️  Starlings AWS Security Scanner v${SCANNER_VERSION}            ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Your credentials never leave your machine."
    echo "  Review the output before sharing."
    echo ""
}

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_finding() {
    local severity=$1
    local message=$2
    case $severity in
        critical) echo -e "  ${RED}[CRITICAL]${NC} $message" ;;
        high)     echo -e "  ${RED}[HIGH]${NC} $message" ;;
        medium)   echo -e "  ${YELLOW}[MEDIUM]${NC} $message" ;;
        low)      echo -e "  ${GREEN}[LOW]${NC} $message" ;;
        pass)     echo -e "  ${GREEN}[PASS]${NC} $message" ;;
    esac
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -r, --region REGION    AWS region to scan (default: all configured regions)"
    echo "  -o, --output FILE      Output file (default: ${DEFAULT_OUTPUT})"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                           # Scan default region"
    echo "  $0 --region us-east-1        # Scan specific region"
    echo "  $0 --output my-report.json   # Custom output file"
    echo ""
}

check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check AWS CLI
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI not found. Please install it first."
        echo "  See: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        exit 1
    fi
    print_success "AWS CLI found"
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured or invalid."
        echo "  Run: aws configure"
        exit 1
    fi
    print_success "AWS credentials valid"
    
    # Check jq
    if ! command -v jq &> /dev/null; then
        print_warning "jq not found. Output will be less formatted."
        JQ_AVAILABLE=false
    else
        JQ_AVAILABLE=true
        print_success "jq found"
    fi
}

get_region() {
    if [ -n "$REGION" ]; then
        echo "$REGION"
    else
        aws configure get region 2>/dev/null || echo "us-east-1"
    fi
}

# ============================================================================
# Findings Storage
# ============================================================================

declare -a FINDINGS=()
declare -i CRITICAL_COUNT=0
declare -i HIGH_COUNT=0
declare -i MEDIUM_COUNT=0
declare -i LOW_COUNT=0
declare -i PASS_COUNT=0

add_finding() {
    local domain=$1
    local check_id=$2
    local severity=$3
    local title=$4
    local description=$5
    local resources=$6
    local remediation=$7
    
    case $severity in
        critical) ((CRITICAL_COUNT++)) ;;
        high)     ((HIGH_COUNT++)) ;;
        medium)   ((MEDIUM_COUNT++)) ;;
        low)      ((LOW_COUNT++)) ;;
    esac
    
    # Escape quotes in strings for JSON
    description=$(echo "$description" | sed 's/"/\\"/g')
    remediation=$(echo "$remediation" | sed 's/"/\\"/g')
    
    FINDINGS+=("{\"domain\":\"$domain\",\"check_id\":\"$check_id\",\"severity\":\"$severity\",\"title\":\"$title\",\"description\":\"$description\",\"resources\":$resources,\"remediation\":\"$remediation\"}")
}

add_pass() {
    ((PASS_COUNT++))
}

# ============================================================================
# IAM Checks
# ============================================================================

check_iam() {
    print_status "Checking IAM & Access Management..."
    local region=$(get_region)
    
    # Check 1: Root account MFA
    print_status "  Checking root account MFA..."
    local account_summary=$(aws iam get-account-summary --query 'SummaryMap' 2>/dev/null || echo "{}")
    local root_mfa=$(echo "$account_summary" | grep -o '"AccountMFAEnabled":[0-9]*' | cut -d: -f2)
    
    if [ "$root_mfa" = "0" ] || [ -z "$root_mfa" ]; then
        add_finding "iam" "IAM-001" "critical" \
            "Root account MFA not enabled" \
            "The root account does not have multi-factor authentication enabled. This is the most privileged account and must be protected." \
            "[]" \
            "Enable MFA on the root account immediately via IAM console > Security credentials"
        print_finding "critical" "Root account MFA not enabled"
    else
        add_pass
        print_finding "pass" "Root account MFA enabled"
    fi
    
    # Check 2: Password policy
    print_status "  Checking password policy..."
    local password_policy=$(aws iam get-account-password-policy 2>/dev/null || echo "")
    
    if [ -z "$password_policy" ]; then
        add_finding "iam" "IAM-002" "high" \
            "No password policy configured" \
            "No custom password policy is set. AWS will use default weak policy." \
            "[]" \
            "Create a password policy requiring minimum 14 characters, complexity, and rotation"
        print_finding "high" "No password policy configured"
    else
        local min_length=$(echo "$password_policy" | grep -o '"MinimumPasswordLength":[0-9]*' | cut -d: -f2)
        if [ -n "$min_length" ] && [ "$min_length" -lt 14 ]; then
            add_finding "iam" "IAM-002" "medium" \
                "Weak password policy" \
                "Password policy allows passwords shorter than 14 characters (current: $min_length)" \
                "[]" \
                "Update password policy to require at least 14 characters"
            print_finding "medium" "Password policy allows short passwords (min: $min_length)"
        else
            add_pass
            print_finding "pass" "Password policy meets minimum length requirements"
        fi
    fi
    
    # Check 3: Users without MFA
    print_status "  Checking user MFA status..."
    local users=$(aws iam list-users --query 'Users[*].UserName' --output text 2>/dev/null || echo "")
    local users_without_mfa=()
    
    for user in $users; do
        local mfa_devices=$(aws iam list-mfa-devices --user-name "$user" --query 'MFADevices' --output text 2>/dev/null || echo "")
        if [ -z "$mfa_devices" ]; then
            users_without_mfa+=("$user")
        fi
    done
    
    if [ ${#users_without_mfa[@]} -gt 0 ]; then
        local user_list=$(printf '"%s",' "${users_without_mfa[@]}" | sed 's/,$//')
        add_finding "iam" "IAM-003" "high" \
            "Users without MFA" \
            "${#users_without_mfa[@]} IAM user(s) do not have MFA enabled" \
            "[$user_list]" \
            "Enable MFA for all IAM users, especially those with console access"
        print_finding "high" "${#users_without_mfa[@]} user(s) without MFA"
    else
        add_pass
        print_finding "pass" "All users have MFA enabled"
    fi
    
    # Check 4: Old access keys (>90 days)
    print_status "  Checking access key age..."
    local old_keys=()
    local ninety_days_ago=$(date -d "90 days ago" +%Y-%m-%d 2>/dev/null || date -v-90d +%Y-%m-%d 2>/dev/null || echo "")
    
    if [ -n "$ninety_days_ago" ]; then
        for user in $users; do
            local keys=$(aws iam list-access-keys --user-name "$user" --query "AccessKeyMetadata[?CreateDate<='${ninety_days_ago}'].AccessKeyId" --output text 2>/dev/null || echo "")
            for key in $keys; do
                old_keys+=("$user:$key")
            done
        done
        
        if [ ${#old_keys[@]} -gt 0 ]; then
            add_finding "iam" "IAM-004" "medium" \
                "Old access keys detected" \
                "${#old_keys[@]} access key(s) are older than 90 days" \
                "[]" \
                "Rotate access keys regularly (at least every 90 days)"
            print_finding "medium" "${#old_keys[@]} access key(s) older than 90 days"
        else
            add_pass
            print_finding "pass" "No access keys older than 90 days"
        fi
    fi
    
    # Check 5: Inactive users (no login in 90 days)
    print_status "  Checking for inactive users..."
    # This requires credential report - skip if not available
    aws iam generate-credential-report &>/dev/null || true
    sleep 2
    local cred_report=$(aws iam get-credential-report --query 'Content' --output text 2>/dev/null | base64 -d 2>/dev/null || echo "")
    
    if [ -n "$cred_report" ]; then
        local inactive_count=$(echo "$cred_report" | awk -F, 'NR>1 && $5!="N/A" && $5!="no_information" {
            split($5,a,"T"); 
            if (a[1] < "'$ninety_days_ago'") count++
        } END {print count+0}')
        
        if [ "$inactive_count" -gt 0 ]; then
            add_finding "iam" "IAM-005" "medium" \
                "Inactive users detected" \
                "$inactive_count user(s) have not logged in for over 90 days" \
                "[]" \
                "Review and disable or remove inactive user accounts"
            print_finding "medium" "$inactive_count inactive user(s) detected"
        else
            add_pass
            print_finding "pass" "No inactive users found"
        fi
    fi
    
    # Check 6: Overly permissive policies (AdministratorAccess on users)
    print_status "  Checking for overprivileged users..."
    local admin_users=()
    
    for user in $users; do
        local attached=$(aws iam list-attached-user-policies --user-name "$user" --query "AttachedPolicies[?PolicyName=='AdministratorAccess'].PolicyName" --output text 2>/dev/null || echo "")
        if [ -n "$attached" ]; then
            admin_users+=("$user")
        fi
    done
    
    if [ ${#admin_users[@]} -gt 0 ]; then
        local admin_list=$(printf '"%s",' "${admin_users[@]}" | sed 's/,$//')
        add_finding "iam" "IAM-006" "high" \
            "Users with AdministratorAccess" \
            "${#admin_users[@]} user(s) have full AdministratorAccess policy attached" \
            "[$admin_list]" \
            "Apply principle of least privilege - use specific policies instead of AdministratorAccess"
        print_finding "high" "${#admin_users[@]} user(s) with AdministratorAccess"
    else
        add_pass
        print_finding "pass" "No users with direct AdministratorAccess"
    fi
}

# ============================================================================
# S3 Checks
# ============================================================================

check_s3() {
    print_status "Checking S3 Bucket Security..."
    
    # Get all buckets
    local buckets=$(aws s3api list-buckets --query 'Buckets[*].Name' --output text 2>/dev/null || echo "")
    
    if [ -z "$buckets" ]; then
        print_warning "  No S3 buckets found or unable to list buckets"
        return
    fi
    
    local public_buckets=()
    local unencrypted_buckets=()
    local no_logging_buckets=()
    local no_versioning_buckets=()
    local bucket_count=0
    
    for bucket in $buckets; do
        ((bucket_count++))
        
        # Check 1: Public access
        local public_access=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null || echo "")
        local bucket_acl=$(aws s3api get-bucket-acl --bucket "$bucket" --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers` || Grantee.URI==`http://acs.amazonaws.com/groups/global/AuthenticatedUsers`]' --output text 2>/dev/null || echo "")
        
        if [ -z "$public_access" ] || [ -n "$bucket_acl" ]; then
            local is_public=false
            if [ -n "$bucket_acl" ]; then
                is_public=true
            fi
            if [ -z "$public_access" ]; then
                is_public=true
            else
                # Check if all blocks are true
                local all_blocked=$(echo "$public_access" | grep -c "true" || echo "0")
                if [ "$all_blocked" -lt 4 ]; then
                    is_public=true
                fi
            fi
            
            if [ "$is_public" = true ]; then
                public_buckets+=("$bucket")
            fi
        fi
        
        # Check 2: Encryption
        local encryption=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null || echo "")
        if [ -z "$encryption" ]; then
            unencrypted_buckets+=("$bucket")
        fi
        
        # Check 3: Logging
        local logging=$(aws s3api get-bucket-logging --bucket "$bucket" --query 'LoggingEnabled' --output text 2>/dev/null || echo "")
        if [ -z "$logging" ] || [ "$logging" = "None" ]; then
            no_logging_buckets+=("$bucket")
        fi
        
        # Check 4: Versioning
        local versioning=$(aws s3api get-bucket-versioning --bucket "$bucket" --query 'Status' --output text 2>/dev/null || echo "")
        if [ -z "$versioning" ] || [ "$versioning" = "None" ] || [ "$versioning" = "Suspended" ]; then
            no_versioning_buckets+=("$bucket")
        fi
    done
    
    print_status "  Scanned $bucket_count buckets"
    
    # Report findings
    if [ ${#public_buckets[@]} -gt 0 ]; then
        local bucket_list=$(printf '"%s",' "${public_buckets[@]}" | sed 's/,$//')
        add_finding "s3" "S3-001" "critical" \
            "Publicly accessible S3 buckets" \
            "${#public_buckets[@]} bucket(s) may be publicly accessible" \
            "[$bucket_list]" \
            "Enable S3 Block Public Access at account and bucket level"
        print_finding "critical" "${#public_buckets[@]} potentially public bucket(s)"
    else
        add_pass
        print_finding "pass" "No publicly accessible buckets found"
    fi
    
    if [ ${#unencrypted_buckets[@]} -gt 0 ]; then
        local bucket_list=$(printf '"%s",' "${unencrypted_buckets[@]}" | sed 's/,$//')
        add_finding "s3" "S3-002" "high" \
            "Unencrypted S3 buckets" \
            "${#unencrypted_buckets[@]} bucket(s) do not have default encryption enabled" \
            "[$bucket_list]" \
            "Enable default encryption (SSE-S3 or SSE-KMS) on all buckets"
        print_finding "high" "${#unencrypted_buckets[@]} unencrypted bucket(s)"
    else
        add_pass
        print_finding "pass" "All buckets have encryption enabled"
    fi
    
    if [ ${#no_logging_buckets[@]} -gt 0 ]; then
        add_finding "s3" "S3-003" "medium" \
            "S3 buckets without access logging" \
            "${#no_logging_buckets[@]} bucket(s) do not have access logging enabled" \
            "[]" \
            "Enable server access logging for audit trail"
        print_finding "medium" "${#no_logging_buckets[@]} bucket(s) without logging"
    else
        add_pass
        print_finding "pass" "All buckets have logging enabled"
    fi
    
    if [ ${#no_versioning_buckets[@]} -gt 0 ]; then
        add_finding "s3" "S3-004" "low" \
            "S3 buckets without versioning" \
            "${#no_versioning_buckets[@]} bucket(s) do not have versioning enabled" \
            "[]" \
            "Enable versioning for data protection and recovery"
        print_finding "low" "${#no_versioning_buckets[@]} bucket(s) without versioning"
    else
        add_pass
        print_finding "pass" "All buckets have versioning enabled"
    fi
}

# ============================================================================
# EC2 & Network Checks
# ============================================================================

check_ec2() {
    print_status "Checking EC2 & Network Security..."
    local region=$(get_region)
    
    # Get all security groups
    local sgs=$(aws ec2 describe-security-groups --region "$region" --query 'SecurityGroups[*].[GroupId,GroupName]' --output text 2>/dev/null || echo "")
    
    if [ -z "$sgs" ]; then
        print_warning "  No security groups found or unable to list"
        return
    fi
    
    local open_ssh=()
    local open_rdp=()
    local open_all=()
    
    # Check each security group
    while IFS=$'\t' read -r sg_id sg_name; do
        # Check for 0.0.0.0/0 on SSH (22)
        local ssh_open=$(aws ec2 describe-security-groups --region "$region" --group-ids "$sg_id" \
            --query "SecurityGroups[*].IpPermissions[?FromPort==\`22\` && ToPort==\`22\`].IpRanges[?CidrIp==\`0.0.0.0/0\`]" \
            --output text 2>/dev/null || echo "")
        if [ -n "$ssh_open" ]; then
            open_ssh+=("$sg_id ($sg_name)")
        fi
        
        # Check for 0.0.0.0/0 on RDP (3389)
        local rdp_open=$(aws ec2 describe-security-groups --region "$region" --group-ids "$sg_id" \
            --query "SecurityGroups[*].IpPermissions[?FromPort==\`3389\` && ToPort==\`3389\`].IpRanges[?CidrIp==\`0.0.0.0/0\`]" \
            --output text 2>/dev/null || echo "")
        if [ -n "$rdp_open" ]; then
            open_rdp+=("$sg_id ($sg_name)")
        fi
        
        # Check for 0.0.0.0/0 on all ports
        local all_open=$(aws ec2 describe-security-groups --region "$region" --group-ids "$sg_id" \
            --query "SecurityGroups[*].IpPermissions[?FromPort==\`-1\` || (FromPort==\`0\` && ToPort==\`65535\`)].IpRanges[?CidrIp==\`0.0.0.0/0\`]" \
            --output text 2>/dev/null || echo "")
        if [ -n "$all_open" ]; then
            open_all+=("$sg_id ($sg_name)")
        fi
    done <<< "$sgs"
    
    # Report findings
    if [ ${#open_ssh[@]} -gt 0 ]; then
        local sg_list=$(printf '"%s",' "${open_ssh[@]}" | sed 's/,$//')
        add_finding "ec2" "EC2-001" "critical" \
            "SSH open to the world" \
            "${#open_ssh[@]} security group(s) allow SSH (port 22) from 0.0.0.0/0" \
            "[$sg_list]" \
            "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager"
        print_finding "critical" "${#open_ssh[@]} security group(s) with SSH open to world"
    else
        add_pass
        print_finding "pass" "No security groups with SSH open to world"
    fi
    
    if [ ${#open_rdp[@]} -gt 0 ]; then
        local sg_list=$(printf '"%s",' "${open_rdp[@]}" | sed 's/,$//')
        add_finding "ec2" "EC2-002" "critical" \
            "RDP open to the world" \
            "${#open_rdp[@]} security group(s) allow RDP (port 3389) from 0.0.0.0/0" \
            "[$sg_list]" \
            "Restrict RDP access to specific IP ranges or use a bastion host"
        print_finding "critical" "${#open_rdp[@]} security group(s) with RDP open to world"
    else
        add_pass
        print_finding "pass" "No security groups with RDP open to world"
    fi
    
    if [ ${#open_all[@]} -gt 0 ]; then
        local sg_list=$(printf '"%s",' "${open_all[@]}" | sed 's/,$//')
        add_finding "ec2" "EC2-003" "critical" \
            "Security groups allow all traffic from anywhere" \
            "${#open_all[@]} security group(s) allow all traffic from 0.0.0.0/0" \
            "[$sg_list]" \
            "Implement least privilege - only allow necessary ports from specific sources"
        print_finding "critical" "${#open_all[@]} security group(s) allow all traffic from anywhere"
    else
        add_pass
        print_finding "pass" "No security groups allowing all traffic from anywhere"
    fi
    
    # Check for unencrypted EBS volumes
    print_status "  Checking EBS encryption..."
    local unencrypted_volumes=$(aws ec2 describe-volumes --region "$region" \
        --query "Volumes[?Encrypted==\`false\`].VolumeId" --output text 2>/dev/null || echo "")
    local unencrypted_count=$(echo "$unencrypted_volumes" | wc -w | tr -d ' ')
    
    if [ "$unencrypted_count" -gt 0 ]; then
        add_finding "ec2" "EC2-004" "high" \
            "Unencrypted EBS volumes" \
            "$unencrypted_count EBS volume(s) are not encrypted" \
            "[]" \
            "Enable EBS encryption by default and encrypt existing volumes"
        print_finding "high" "$unencrypted_count unencrypted EBS volume(s)"
    else
        add_pass
        print_finding "pass" "All EBS volumes are encrypted"
    fi
    
    # Check for instances with public IPs
    print_status "  Checking public IP exposure..."
    local public_instances=$(aws ec2 describe-instances --region "$region" \
        --query "Reservations[*].Instances[?PublicIpAddress!=null].InstanceId" --output text 2>/dev/null || echo "")
    local public_count=$(echo "$public_instances" | wc -w | tr -d ' ')
    
    if [ "$public_count" -gt 0 ]; then
        add_finding "ec2" "EC2-005" "medium" \
            "EC2 instances with public IP addresses" \
            "$public_count instance(s) have public IP addresses" \
            "[]" \
            "Review if public IPs are necessary. Consider using NAT Gateway or private subnets"
        print_finding "medium" "$public_count instance(s) with public IPs"
    else
        add_pass
        print_finding "pass" "No instances with public IPs"
    fi
    
    # Check for IMDSv1 (vulnerable to SSRF)
    print_status "  Checking IMDS configuration..."
    local imdsv1_instances=$(aws ec2 describe-instances --region "$region" \
        --query "Reservations[*].Instances[?MetadataOptions.HttpTokens!='required'].InstanceId" --output text 2>/dev/null || echo "")
    local imdsv1_count=$(echo "$imdsv1_instances" | wc -w | tr -d ' ')
    
    if [ "$imdsv1_count" -gt 0 ]; then
        add_finding "ec2" "EC2-006" "high" \
            "Instances allow IMDSv1" \
            "$imdsv1_count instance(s) allow IMDSv1 (vulnerable to SSRF attacks)" \
            "[]" \
            "Enforce IMDSv2 by setting HttpTokens to 'required'"
        print_finding "high" "$imdsv1_count instance(s) allow IMDSv1"
    else
        add_pass
        print_finding "pass" "All instances enforce IMDSv2"
    fi
}

# ============================================================================
# RDS Checks
# ============================================================================

check_rds() {
    print_status "Checking RDS & Database Security..."
    local region=$(get_region)
    
    # Get all RDS instances
    local instances=$(aws rds describe-db-instances --region "$region" \
        --query 'DBInstances[*].DBInstanceIdentifier' --output text 2>/dev/null || echo "")
    
    if [ -z "$instances" ]; then
        print_status "  No RDS instances found"
        return
    fi
    
    local public_instances=()
    local unencrypted_instances=()
    local no_backup_instances=()
    
    for instance in $instances; do
        local details=$(aws rds describe-db-instances --region "$region" \
            --db-instance-identifier "$instance" \
            --query 'DBInstances[0].[PubliclyAccessible,StorageEncrypted,BackupRetentionPeriod]' \
            --output text 2>/dev/null || echo "")
        
        local publicly_accessible=$(echo "$details" | awk '{print $1}')
        local encrypted=$(echo "$details" | awk '{print $2}')
        local backup_retention=$(echo "$details" | awk '{print $3}')
        
        if [ "$publicly_accessible" = "True" ]; then
            public_instances+=("$instance")
        fi
        
        if [ "$encrypted" = "False" ]; then
            unencrypted_instances+=("$instance")
        fi
        
        if [ "$backup_retention" = "0" ]; then
            no_backup_instances+=("$instance")
        fi
    done
    
    # Report findings
    if [ ${#public_instances[@]} -gt 0 ]; then
        local instance_list=$(printf '"%s",' "${public_instances[@]}" | sed 's/,$//')
        add_finding "rds" "RDS-001" "critical" \
            "Publicly accessible RDS instances" \
            "${#public_instances[@]} RDS instance(s) are publicly accessible" \
            "[$instance_list]" \
            "Disable public accessibility and use private subnets with VPC security groups"
        print_finding "critical" "${#public_instances[@]} publicly accessible RDS instance(s)"
    else
        add_pass
        print_finding "pass" "No publicly accessible RDS instances"
    fi
    
    if [ ${#unencrypted_instances[@]} -gt 0 ]; then
        local instance_list=$(printf '"%s",' "${unencrypted_instances[@]}" | sed 's/,$//')
        add_finding "rds" "RDS-002" "high" \
            "Unencrypted RDS instances" \
            "${#unencrypted_instances[@]} RDS instance(s) are not encrypted" \
            "[$instance_list]" \
            "Enable encryption for RDS instances (requires snapshot and restore for existing)"
        print_finding "high" "${#unencrypted_instances[@]} unencrypted RDS instance(s)"
    else
        add_pass
        print_finding "pass" "All RDS instances are encrypted"
    fi
    
    if [ ${#no_backup_instances[@]} -gt 0 ]; then
        local instance_list=$(printf '"%s",' "${no_backup_instances[@]}" | sed 's/,$//')
        add_finding "rds" "RDS-003" "high" \
            "RDS instances without backups" \
            "${#no_backup_instances[@]} RDS instance(s) have backup retention set to 0" \
            "[$instance_list]" \
            "Enable automated backups with at least 7 days retention"
        print_finding "high" "${#no_backup_instances[@]} RDS instance(s) without backups"
    else
        add_pass
        print_finding "pass" "All RDS instances have backups enabled"
    fi
}

# ============================================================================
# Logging & Monitoring Checks
# ============================================================================

check_logging() {
    print_status "Checking Logging & Monitoring..."
    local region=$(get_region)
    
    # Check 1: CloudTrail enabled
    print_status "  Checking CloudTrail..."
    local trails=$(aws cloudtrail describe-trails --region "$region" \
        --query 'trailList[*].Name' --output text 2>/dev/null || echo "")
    
    if [ -z "$trails" ]; then
        add_finding "logging" "LOG-001" "critical" \
            "CloudTrail not enabled" \
            "No CloudTrail trails are configured in this region" \
            "[]" \
            "Enable CloudTrail with multi-region logging and log file validation"
        print_finding "critical" "CloudTrail not enabled"
    else
        add_pass
        print_finding "pass" "CloudTrail is enabled"
        
        # Check trail configuration
        for trail in $trails; do
            local trail_config=$(aws cloudtrail describe-trails --region "$region" \
                --trail-name-list "$trail" \
                --query 'trailList[0].[IsMultiRegionTrail,LogFileValidationEnabled,KMSKeyId]' \
                --output text 2>/dev/null || echo "")
            
            local multi_region=$(echo "$trail_config" | awk '{print $1}')
            local log_validation=$(echo "$trail_config" | awk '{print $2}')
            local kms_key=$(echo "$trail_config" | awk '{print $3}')
            
            if [ "$multi_region" = "False" ]; then
                add_finding "logging" "LOG-002" "high" \
                    "CloudTrail not multi-region" \
                    "Trail '$trail' is not configured for multi-region logging" \
                    "[\"$trail\"]" \
                    "Enable multi-region logging to capture API calls in all regions"
                print_finding "high" "CloudTrail '$trail' not multi-region"
            else
                add_pass
            fi
            
            if [ "$log_validation" = "False" ]; then
                add_finding "logging" "LOG-003" "medium" \
                    "CloudTrail log validation disabled" \
                    "Trail '$trail' does not have log file validation enabled" \
                    "[\"$trail\"]" \
                    "Enable log file validation to detect tampering"
                print_finding "medium" "CloudTrail '$trail' log validation disabled"
            else
                add_pass
            fi
            
            if [ "$kms_key" = "None" ] || [ -z "$kms_key" ]; then
                add_finding "logging" "LOG-004" "medium" \
                    "CloudTrail logs not encrypted with KMS" \
                    "Trail '$trail' logs are not encrypted with a KMS key" \
                    "[\"$trail\"]" \
                    "Enable KMS encryption for CloudTrail logs"
                print_finding "medium" "CloudTrail '$trail' not KMS encrypted"
            else
                add_pass
            fi
        done
    fi
    
    # Check 2: GuardDuty enabled
    print_status "  Checking GuardDuty..."
    local guardduty=$(aws guardduty list-detectors --region "$region" \
        --query 'DetectorIds' --output text 2>/dev/null || echo "")
    
    if [ -z "$guardduty" ]; then
        add_finding "logging" "LOG-005" "high" \
            "GuardDuty not enabled" \
            "Amazon GuardDuty is not enabled in this region" \
            "[]" \
            "Enable GuardDuty for threat detection and continuous monitoring"
        print_finding "high" "GuardDuty not enabled"
    else
        add_pass
        print_finding "pass" "GuardDuty is enabled"
    fi
    
    # Check 3: AWS Config enabled
    print_status "  Checking AWS Config..."
    local config_recorders=$(aws configservice describe-configuration-recorders --region "$region" \
        --query 'ConfigurationRecorders[*].name' --output text 2>/dev/null || echo "")
    
    if [ -z "$config_recorders" ]; then
        add_finding "logging" "LOG-006" "high" \
            "AWS Config not enabled" \
            "AWS Config is not enabled in this region" \
            "[]" \
            "Enable AWS Config to track resource configurations and changes"
        print_finding "high" "AWS Config not enabled"
    else
        add_pass
        print_finding "pass" "AWS Config is enabled"
    fi
    
    # Check 4: Security Hub enabled
    print_status "  Checking Security Hub..."
    local security_hub=$(aws securityhub describe-hub --region "$region" 2>/dev/null || echo "")
    
    if [ -z "$security_hub" ]; then
        add_finding "logging" "LOG-007" "medium" \
            "Security Hub not enabled" \
            "AWS Security Hub is not enabled in this region" \
            "[]" \
            "Enable Security Hub for centralized security findings and compliance checks"
        print_finding "medium" "Security Hub not enabled"
    else
        add_pass
        print_finding "pass" "Security Hub is enabled"
    fi
}

# ============================================================================
# KMS Checks
# ============================================================================

check_kms() {
    print_status "Checking KMS & Encryption..."
    local region=$(get_region)
    
    # Get customer managed keys
    local keys=$(aws kms list-keys --region "$region" \
        --query 'Keys[*].KeyId' --output text 2>/dev/null || echo "")
    
    if [ -z "$keys" ]; then
        print_status "  No customer managed KMS keys found"
        return
    fi
    
    local no_rotation=()
    
    for key in $keys; do
        # Check if it's customer managed (not AWS managed)
        local key_manager=$(aws kms describe-key --region "$region" --key-id "$key" \
            --query 'KeyMetadata.KeyManager' --output text 2>/dev/null || echo "")
        
        if [ "$key_manager" = "CUSTOMER" ]; then
            local rotation=$(aws kms get-key-rotation-status --region "$region" --key-id "$key" \
                --query 'KeyRotationEnabled' --output text 2>/dev/null || echo "")
            
            if [ "$rotation" = "False" ]; then
                no_rotation+=("$key")
            fi
        fi
    done
    
    if [ ${#no_rotation[@]} -gt 0 ]; then
        add_finding "kms" "KMS-001" "medium" \
            "KMS keys without automatic rotation" \
            "${#no_rotation[@]} customer managed KMS key(s) do not have automatic rotation enabled" \
            "[]" \
            "Enable automatic key rotation for customer managed KMS keys"
        print_finding "medium" "${#no_rotation[@]} KMS key(s) without rotation"
    else
        add_pass
        print_finding "pass" "All customer managed KMS keys have rotation enabled"
    fi
}

# ============================================================================
# Report Generation
# ============================================================================

calculate_score() {
    local max_checks=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT + PASS_COUNT))
    
    if [ "$max_checks" -eq 0 ]; then
        echo "0"
        return
    fi
    
    # Weighted deductions
    local deductions=$((CRITICAL_COUNT * 15 + HIGH_COUNT * 8 + MEDIUM_COUNT * 3 + LOW_COUNT * 1))
    local max_score=$((max_checks * 10))
    local raw_score=$((max_score - deductions))
    
    if [ "$raw_score" -lt 0 ]; then
        raw_score=0
    fi
    
    local percentage=$((raw_score * 100 / max_score))
    echo "$percentage"
}

get_interpretation() {
    local score=$1
    if [ "$score" -ge 90 ]; then
        echo "Excellent"
    elif [ "$score" -ge 70 ]; then
        echo "Good"
    elif [ "$score" -ge 50 ]; then
        echo "Fair"
    else
        echo "Needs Attention"
    fi
}

generate_report() {
    local score=$(calculate_score)
    local interpretation=$(get_interpretation "$score")
    local scan_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local region=$(get_region)
    
    # Build findings JSON array
    local findings_json=""
    for finding in "${FINDINGS[@]}"; do
        if [ -n "$findings_json" ]; then
            findings_json="$findings_json,"
        fi
        findings_json="$findings_json$finding"
    done
    
    # Generate report
    cat > "$OUTPUT_FILE" << EOF
{
  "scanner_version": "$SCANNER_VERSION",
  "scan_date": "$scan_date",
  "region": "$region",
  "score": {
    "overall": $score,
    "interpretation": "$interpretation"
  },
  "summary": {
    "critical": $CRITICAL_COUNT,
    "high": $HIGH_COUNT,
    "medium": $MEDIUM_COUNT,
    "low": $LOW_COUNT,
    "passed": $PASS_COUNT,
    "total_checks": $((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT + PASS_COUNT))
  },
  "findings": [$findings_json]
}
EOF

    # Redact sensitive information
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' 's/[0-9]\{12\}/REDACTED/g' "$OUTPUT_FILE"
    else
        sed -i 's/[0-9]\{12\}/REDACTED/g' "$OUTPUT_FILE"
    fi
    
    # Pretty print if jq available
    if [ "$JQ_AVAILABLE" = true ]; then
        local temp_file=$(mktemp)
        jq '.' "$OUTPUT_FILE" > "$temp_file" && mv "$temp_file" "$OUTPUT_FILE"
    fi
}

print_summary() {
    local score=$(calculate_score)
    local interpretation=$(get_interpretation "$score")
    
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Security Score: ${BLUE}$score/100${NC} ($interpretation)"
    echo ""
    echo "  Summary:"
    echo -e "    ${RED}Critical:${NC} $CRITICAL_COUNT"
    echo -e "    ${RED}High:${NC}     $HIGH_COUNT"
    echo -e "    ${YELLOW}Medium:${NC}   $MEDIUM_COUNT"
    echo -e "    ${GREEN}Low:${NC}      $LOW_COUNT"
    echo -e "    ${GREEN}Passed:${NC}   $PASS_COUNT"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Report saved to: ${GREEN}$OUTPUT_FILE${NC}"
    echo ""
    echo "  Next steps:"
    echo "    1. Review the report for sensitive information"
    echo "    2. Share it at: https://scamshield.app/audit"
    echo "    3. Get your personalized remediation plan"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -r|--region)
                REGION="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
    
    # Set default output file
    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="$DEFAULT_OUTPUT"
    fi
    
    print_banner
    check_prerequisites
    
    echo ""
    echo -e "${BLUE}Starting security scan...${NC}"
    echo ""
    
    # Run all checks
    check_iam
    echo ""
    check_s3
    echo ""
    check_ec2
    echo ""
    check_rds
    echo ""
    check_logging
    echo ""
    check_kms
    
    # Generate report
    generate_report
    
    # Print summary
    print_summary
}

main "$@"
