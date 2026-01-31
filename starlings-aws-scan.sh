#!/bin/bash
#
# Starlings AWS Security Scanner v1.1
# ====================================
# 
# This script runs locally in YOUR environment.
# Your AWS credentials NEVER leave your machine.
#
# What it does:
#   - Runs read-only checks against your AWS account
#   - Identifies security misconfigurations
#   - Maps findings to compliance frameworks (ISO 27001, SOC 2, CIS, CCSS)
#   - Outputs a JSON report you can review before sharing
#
# Requirements:
#   - AWS CLI installed and configured
#   - Read-only permissions (see scan-policy.json for minimal IAM policy)
#
# Usage:
#   ./starlings-aws-scan.sh [--region REGION] [--output FILE] [--all-regions]
#
# Source: https://github.com/Starlings-Data/aws-scanner
# License: MIT
#

set -e

# Force JSON output regardless of user's AWS CLI config
export AWS_DEFAULT_OUTPUT=json

# ============================================================================
# Configuration
# ============================================================================

SCANNER_VERSION="1.2.0"
DEFAULT_OUTPUT="aws-security-report.json"
REGION=""
OUTPUT_FILE=""
PROFILE=""
PROFILE_ARG=""
ALL_REGIONS=false
VERBOSE=false

# Colors for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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
    echo "  -p, --profile PROFILE  AWS CLI profile to use (for SSO or named profiles)"
    echo "  -r, --region REGION    AWS region to scan (default: from AWS CLI config)"
    echo "  -o, --output FILE      Output file (default: ${DEFAULT_OUTPUT})"
    echo "  -a, --all-regions      Scan all available regions"
    echo "  -v, --verbose          Verbose output"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                              # Scan with default credentials"
    echo "  $0 --profile my-sso-profile     # Scan using SSO profile"
    echo "  $0 --region us-east-1           # Scan specific region"
    echo "  $0 --all-regions                # Scan all regions"
    echo "  $0 --output my-report.json      # Custom output file"
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
    
    # Set up profile argument if specified
    if [ -n "$PROFILE" ]; then
        PROFILE_ARG="--profile $PROFILE"
        print_status "Using profile: $PROFILE"
    fi
    
    # Check AWS credentials with better error handling
    local cred_check
    cred_check=$(aws sts get-caller-identity $PROFILE_ARG 2>&1)
    local cred_exit=$?
    
    if [ $cred_exit -ne 0 ]; then
        print_error "AWS credentials not configured or invalid."
        # Show helpful hints based on the error
        if echo "$cred_check" | grep -q "InvalidClientTokenId"; then
            echo "  Access keys are invalid or expired."
            echo "  Run: aws configure"
            echo "  Or use SSO: aws sso login --profile YOUR_PROFILE"
        elif echo "$cred_check" | grep -q "ExpiredToken"; then
            echo "  Session expired. Run: aws sso login"
        elif echo "$cred_check" | grep -q "could not be found"; then
            echo "  Profile '$PROFILE' not found in ~/.aws/config"
        else
            echo "  $cred_check"
        fi
        exit 1
    fi
    print_success "AWS credentials valid"
    
    # Get account ID for reference
    ACCOUNT_ID=$(aws sts get-caller-identity $PROFILE_ARG --query 'Account' --output text 2>/dev/null || echo "unknown")
    print_status "Account ID: $ACCOUNT_ID"
    
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
        aws configure get region $PROFILE_ARG 2>/dev/null || echo "us-east-1"
    fi
}

get_all_regions() {
    aws ec2 describe-regions $PROFILE_ARG --query 'Regions[].RegionName' --output text 2>/dev/null || echo "us-east-1"
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
    local frameworks=$8  # New: compliance framework references
    
    case $severity in
        critical) CRITICAL_COUNT=$((CRITICAL_COUNT + 1)) ;;
        high)     HIGH_COUNT=$((HIGH_COUNT + 1)) ;;
        medium)   MEDIUM_COUNT=$((MEDIUM_COUNT + 1)) ;;
        low)      LOW_COUNT=$((LOW_COUNT + 1)) ;;
    esac
    
    # Escape quotes in strings for JSON
    description=$(echo "$description" | sed 's/"/\\"/g')
    remediation=$(echo "$remediation" | sed 's/"/\\"/g')
    
    # Add frameworks if provided, otherwise use empty array
    if [ -z "$frameworks" ]; then
        frameworks="[]"
    fi
    
    FINDINGS+=("{\"domain\":\"$domain\",\"check_id\":\"$check_id\",\"severity\":\"$severity\",\"title\":\"$title\",\"description\":\"$description\",\"resources\":$resources,\"remediation\":\"$remediation\",\"frameworks\":$frameworks}")
}

add_pass() {
    PASS_COUNT=$((PASS_COUNT + 1))
}

# ============================================================================
# IAM Checks
# ============================================================================

check_iam() {
    print_status "Checking IAM & Access Management..."
    local region=$(get_region)
    
    # Check 1: Root account MFA
    print_status "  Checking root account MFA..."
    local account_summary=$(aws iam get-account-summary $PROFILE_ARG --output json 2>/dev/null || echo "{}")
    local root_mfa=$(echo "$account_summary" | grep -o '"AccountMFAEnabled": *[0-9]*' | grep -o '[0-9]*$' || echo "")
    
    if [ "$root_mfa" = "0" ] || [ -z "$root_mfa" ]; then
        add_finding "iam" "IAM-001" "critical" \
            "Root account MFA not enabled" \
            "The root account does not have multi-factor authentication enabled. This is the most privileged account and must be protected." \
            "[]" \
            "Enable MFA on the root account immediately via IAM console > Security credentials" \
            "[\"CIS 1.5\",\"ISO27001 A.9.4.2\",\"SOC2 CC6.1\",\"CCSS 4.1\"]"
        print_finding "critical" "Root account MFA not enabled"
    else
        add_pass
        print_finding "pass" "Root account MFA enabled"
    fi
    
    # Check 2: Root access keys (should not exist)
    print_status "  Checking root access keys..."
    local root_access_keys=$(echo "$account_summary" | grep -o '"AccountAccessKeysPresent": *[0-9]*' | grep -o '[0-9]*$' || echo "0")
    
    if [ "$root_access_keys" = "1" ]; then
        add_finding "iam" "IAM-002" "critical" \
            "Root account has access keys" \
            "The root account has active access keys. Root access keys pose a severe security risk and should be deleted." \
            "[]" \
            "Delete root account access keys via IAM console. Use IAM users or roles instead." \
            "[\"CIS 1.4\",\"ISO27001 A.9.2.3\",\"SOC2 CC6.1\"]"
        print_finding "critical" "Root account has access keys"
    else
        add_pass
        print_finding "pass" "No root access keys present"
    fi
    
    # Check 3: Password policy
    print_status "  Checking password policy..."
    local password_policy=$(aws iam get-account-password-policy $PROFILE_ARG --output json 2>/dev/null || echo "")
    
    if [ -z "$password_policy" ]; then
        add_finding "iam" "IAM-003" "high" \
            "No password policy configured" \
            "No custom password policy is set. AWS will use default weak policy." \
            "[]" \
            "Create a password policy requiring minimum 14 characters, complexity, and rotation" \
            "[\"CIS 1.8\",\"ISO27001 A.9.4.3\",\"SOC2 CC6.1\",\"CCSS 4.2\"]"
        print_finding "high" "No password policy configured"
    else
        local min_length=$(echo "$password_policy" | grep -o '"MinimumPasswordLength": *[0-9]*' | grep -o '[0-9]*$' || echo "")
        local require_symbols=$(echo "$password_policy" | grep -o '"RequireSymbols": *[a-z]*' | grep -o '[a-z]*$' || echo "")
        local require_numbers=$(echo "$password_policy" | grep -o '"RequireNumbers": *[a-z]*' | grep -o '[a-z]*$' || echo "")
        local require_uppercase=$(echo "$password_policy" | grep -o '"RequireUppercaseCharacters": *[a-z]*' | grep -o '[a-z]*$' || echo "")
        local max_age=$(echo "$password_policy" | grep -o '"MaxPasswordAge": *[0-9]*' | grep -o '[0-9]*$' || echo "")
        
        local policy_issues=()
        
        if [ -n "$min_length" ] && [ "$min_length" -lt 14 ]; then
            policy_issues+=("min length $min_length < 14")
        fi
        if [ "$require_symbols" != "true" ]; then
            policy_issues+=("no symbol requirement")
        fi
        if [ "$require_numbers" != "true" ]; then
            policy_issues+=("no number requirement")
        fi
        if [ "$require_uppercase" != "true" ]; then
            policy_issues+=("no uppercase requirement")
        fi
        if [ -z "$max_age" ] || [ "$max_age" -gt 90 ]; then
            policy_issues+=("password age > 90 days or not set")
        fi
        
        if [ ${#policy_issues[@]} -gt 0 ]; then
            add_finding "iam" "IAM-003" "medium" \
                "Weak password policy" \
                "Password policy has issues: ${policy_issues[*]}" \
                "[]" \
                "Update password policy to require at least 14 characters, symbols, numbers, uppercase, and 90-day rotation" \
                "[\"CIS 1.8-1.11\",\"ISO27001 A.9.4.3\",\"SOC2 CC6.1\"]"
            print_finding "medium" "Password policy has issues: ${policy_issues[*]}"
        else
            add_pass
            print_finding "pass" "Password policy meets requirements"
        fi
    fi
    
    # Check 4: Users without MFA
    print_status "  Checking user MFA status..."
    local users=$(aws iam list-users $PROFILE_ARG --query 'Users[*].UserName' --output text 2>/dev/null || echo "")
    local users_without_mfa=()
    
    for user in $users; do
        local mfa_devices=$(aws iam list-mfa-devices $PROFILE_ARG --user-name "$user" --query 'MFADevices' --output text 2>/dev/null || echo "")
        if [ -z "$mfa_devices" ]; then
            users_without_mfa+=("$user")
        fi
    done
    
    if [ ${#users_without_mfa[@]} -gt 0 ]; then
        local user_list=$(printf '"%s",' "${users_without_mfa[@]}" | sed 's/,$//')
        add_finding "iam" "IAM-004" "high" \
            "Users without MFA" \
            "${#users_without_mfa[@]} IAM user(s) do not have MFA enabled" \
            "[$user_list]" \
            "Enable MFA for all IAM users, especially those with console access" \
            "[\"CIS 1.10\",\"ISO27001 A.9.4.2\",\"SOC2 CC6.1\",\"CCSS 4.1\"]"
        print_finding "high" "${#users_without_mfa[@]} user(s) without MFA"
    else
        add_pass
        print_finding "pass" "All users have MFA enabled"
    fi
    
    # Check 5: Old access keys (>90 days)
    print_status "  Checking access key age..."
    local old_keys=()
    local ninety_days_ago=$(date -d "90 days ago" +%Y-%m-%d 2>/dev/null || date -v-90d +%Y-%m-%d 2>/dev/null || echo "")
    
    if [ -n "$ninety_days_ago" ]; then
        for user in $users; do
            local keys=$(aws iam list-access-keys $PROFILE_ARG --user-name "$user" --query "AccessKeyMetadata[?CreateDate<='${ninety_days_ago}'].AccessKeyId" --output text 2>/dev/null || echo "")
            for key in $keys; do
                old_keys+=("$user:$key")
            done
        done
        
        if [ ${#old_keys[@]} -gt 0 ]; then
            add_finding "iam" "IAM-005" "medium" \
                "Old access keys detected" \
                "${#old_keys[@]} access key(s) are older than 90 days" \
                "[]" \
                "Rotate access keys regularly (at least every 90 days)" \
                "[\"CIS 1.14\",\"ISO27001 A.9.2.5\",\"SOC2 CC6.1\"]"
            print_finding "medium" "${#old_keys[@]} access key(s) older than 90 days"
        else
            add_pass
            print_finding "pass" "No access keys older than 90 days"
        fi
    fi
    
    # Check 6: Unused credentials
    print_status "  Checking for unused credentials..."
    aws iam generate-credential-report $PROFILE_ARG &>/dev/null || true
    sleep 2
    local cred_report=$(aws iam get-credential-report $PROFILE_ARG --query 'Content' --output text 2>/dev/null | base64 -d 2>/dev/null || echo "")
    
    if [ -n "$cred_report" ] && [ -n "$ninety_days_ago" ]; then
        local inactive_count=$(echo "$cred_report" | awk -F, 'NR>1 && $5!="N/A" && $5!="no_information" {
            split($5,a,"T"); 
            if (a[1] < "'$ninety_days_ago'") count++
        } END {print count+0}')
        
        if [ "$inactive_count" -gt 0 ]; then
            add_finding "iam" "IAM-006" "medium" \
                "Inactive users detected" \
                "$inactive_count user(s) have not logged in for over 90 days" \
                "[]" \
                "Review and disable or remove inactive user accounts" \
                "[\"CIS 1.12\",\"ISO27001 A.9.2.6\",\"SOC2 CC6.2\"]"
            print_finding "medium" "$inactive_count inactive user(s) detected"
        else
            add_pass
            print_finding "pass" "No inactive users found"
        fi
    fi
    
    # Check 7: Overly permissive policies (AdministratorAccess on users)
    print_status "  Checking for overprivileged users..."
    local admin_users=()
    
    for user in $users; do
        local attached=$(aws iam list-attached-user-policies $PROFILE_ARG --user-name "$user" --query "AttachedPolicies[?PolicyName=='AdministratorAccess'].PolicyName" --output text 2>/dev/null || echo "")
        if [ -n "$attached" ]; then
            admin_users+=("$user")
        fi
    done
    
    if [ ${#admin_users[@]} -gt 0 ]; then
        local admin_list=$(printf '"%s",' "${admin_users[@]}" | sed 's/,$//')
        add_finding "iam" "IAM-007" "high" \
            "Users with AdministratorAccess" \
            "${#admin_users[@]} user(s) have full AdministratorAccess policy attached" \
            "[$admin_list]" \
            "Apply principle of least privilege - use specific policies instead of AdministratorAccess" \
            "[\"CIS 1.16\",\"ISO27001 A.9.2.3\",\"SOC2 CC6.3\",\"CCSS 4.3\"]"
        print_finding "high" "${#admin_users[@]} user(s) with AdministratorAccess"
    else
        add_pass
        print_finding "pass" "No users with direct AdministratorAccess"
    fi
    
    # Check 8: AWS Support Role exists
    print_status "  Checking AWS Support role..."
    local support_role=$(aws iam get-role $PROFILE_ARG --role-name AWSSupportAccess 2>/dev/null || echo "")
    
    if [ -z "$support_role" ]; then
        add_finding "iam" "IAM-008" "low" \
            "AWS Support role not configured" \
            "No AWSSupportAccess role exists. This role allows AWS Support to assist with troubleshooting." \
            "[]" \
            "Create AWSSupportAccess role with AWSSupportAccess managed policy for support cases" \
            "[\"CIS 1.20\",\"ISO27001 A.6.1.3\"]"
        print_finding "low" "AWS Support role not configured"
    else
        add_pass
        print_finding "pass" "AWS Support role exists"
    fi
}

# ============================================================================
# S3 Checks
# ============================================================================

check_s3() {
    print_status "Checking S3 Bucket Security..."
    
    # Get all buckets
    local buckets=$(aws s3api list-buckets $PROFILE_ARG --query 'Buckets[*].Name' --output text 2>/dev/null || echo "")
    
    if [ -z "$buckets" ]; then
        print_warning "  No S3 buckets found or unable to list buckets"
        return
    fi
    
    local public_buckets=()
    local unencrypted_buckets=()
    local no_logging_buckets=()
    local no_versioning_buckets=()
    local no_ssl_buckets=()
    local bucket_count=0
    
    for bucket in $buckets; do
        ((bucket_count++))
        
        # Check 1: Public access
        local public_access=$(aws s3api get-public-access-block $PROFILE_ARG --bucket "$bucket" 2>/dev/null || echo "")
        local bucket_acl=$(aws s3api get-bucket-acl $PROFILE_ARG --bucket "$bucket" --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers` || Grantee.URI==`http://acs.amazonaws.com/groups/global/AuthenticatedUsers`]' --output text 2>/dev/null || echo "")
        
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
        local encryption=$(aws s3api get-bucket-encryption $PROFILE_ARG --bucket "$bucket" 2>/dev/null || echo "")
        if [ -z "$encryption" ]; then
            unencrypted_buckets+=("$bucket")
        fi
        
        # Check 3: Logging
        local logging=$(aws s3api get-bucket-logging $PROFILE_ARG --bucket "$bucket" --query 'LoggingEnabled' --output text 2>/dev/null || echo "")
        if [ -z "$logging" ] || [ "$logging" = "None" ]; then
            no_logging_buckets+=("$bucket")
        fi
        
        # Check 4: Versioning
        local versioning=$(aws s3api get-bucket-versioning $PROFILE_ARG --bucket "$bucket" --query 'Status' --output text 2>/dev/null || echo "")
        if [ -z "$versioning" ] || [ "$versioning" = "None" ] || [ "$versioning" = "Suspended" ]; then
            no_versioning_buckets+=("$bucket")
        fi
        
        # Check 5: SSL/TLS enforcement (bucket policy requiring SecureTransport)
        local bucket_policy=$(aws s3api get-bucket-policy $PROFILE_ARG --bucket "$bucket" --query 'Policy' --output text 2>/dev/null || echo "")
        if [ -n "$bucket_policy" ]; then
            if ! echo "$bucket_policy" | grep -q "aws:SecureTransport"; then
                no_ssl_buckets+=("$bucket")
            fi
        else
            no_ssl_buckets+=("$bucket")
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
            "Enable S3 Block Public Access at account and bucket level" \
            "[\"CIS 2.1.5\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.1\",\"CCSS 3.1\"]"
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
            "Enable default encryption (SSE-S3 or SSE-KMS) on all buckets" \
            "[\"CIS 2.1.1\",\"ISO27001 A.10.1.1\",\"SOC2 CC6.1\",\"CCSS 3.2\"]"
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
            "Enable server access logging for audit trail" \
            "[\"CIS 2.1.3\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\"]"
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
            "Enable versioning for data protection and recovery" \
            "[\"CIS 2.1.2\",\"ISO27001 A.17.1.1\",\"SOC2 CC9.1\"]"
        print_finding "low" "${#no_versioning_buckets[@]} bucket(s) without versioning"
    else
        add_pass
        print_finding "pass" "All buckets have versioning enabled"
    fi
    
    if [ ${#no_ssl_buckets[@]} -gt 0 ]; then
        add_finding "s3" "S3-005" "medium" \
            "S3 buckets without SSL/TLS enforcement" \
            "${#no_ssl_buckets[@]} bucket(s) do not require secure transport" \
            "[]" \
            "Add bucket policy denying requests without aws:SecureTransport" \
            "[\"CIS 2.1.4\",\"ISO27001 A.14.1.2\",\"SOC2 CC6.7\"]"
        print_finding "medium" "${#no_ssl_buckets[@]} bucket(s) without SSL enforcement"
    else
        add_pass
        print_finding "pass" "All buckets enforce SSL/TLS"
    fi
}

# ============================================================================
# EC2 & Network Checks
# ============================================================================

check_ec2() {
    print_status "Checking EC2 & Network Security..."
    local region=$(get_region)
    
    # Get all security groups
    local sgs=$(aws ec2 describe-security-groups $PROFILE_ARG --region "$region" --query 'SecurityGroups[*].[GroupId,GroupName]' --output text 2>/dev/null || echo "")
    
    if [ -z "$sgs" ]; then
        print_warning "  No security groups found or unable to list"
        return
    fi
    
    local open_ssh=()
    local open_rdp=()
    local open_all=()
    local default_sg_with_rules=()
    
    # Check each security group
    while IFS=$'\t' read -r sg_id sg_name; do
        # Check for 0.0.0.0/0 on SSH (22)
        local ssh_open=$(aws ec2 describe-security-groups $PROFILE_ARG --region "$region" --group-ids "$sg_id" \
            --query "SecurityGroups[*].IpPermissions[?FromPort==\`22\` && ToPort==\`22\`].IpRanges[?CidrIp==\`0.0.0.0/0\`]" \
            --output text 2>/dev/null || echo "")
        if [ -n "$ssh_open" ]; then
            open_ssh+=("$sg_id ($sg_name)")
        fi
        
        # Check for 0.0.0.0/0 on RDP (3389)
        local rdp_open=$(aws ec2 describe-security-groups $PROFILE_ARG --region "$region" --group-ids "$sg_id" \
            --query "SecurityGroups[*].IpPermissions[?FromPort==\`3389\` && ToPort==\`3389\`].IpRanges[?CidrIp==\`0.0.0.0/0\`]" \
            --output text 2>/dev/null || echo "")
        if [ -n "$rdp_open" ]; then
            open_rdp+=("$sg_id ($sg_name)")
        fi
        
        # Check for 0.0.0.0/0 on all ports
        local all_open=$(aws ec2 describe-security-groups $PROFILE_ARG --region "$region" --group-ids "$sg_id" \
            --query "SecurityGroups[*].IpPermissions[?FromPort==\`-1\` || (FromPort==\`0\` && ToPort==\`65535\`)].IpRanges[?CidrIp==\`0.0.0.0/0\`]" \
            --output text 2>/dev/null || echo "")
        if [ -n "$all_open" ]; then
            open_all+=("$sg_id ($sg_name)")
        fi
        
        # Check default security groups (should have no rules)
        if [ "$sg_name" = "default" ]; then
            local inbound_rules=$(aws ec2 describe-security-groups $PROFILE_ARG --region "$region" --group-ids "$sg_id" \
                --query "SecurityGroups[*].IpPermissions" --output text 2>/dev/null || echo "")
            local outbound_rules=$(aws ec2 describe-security-groups $PROFILE_ARG --region "$region" --group-ids "$sg_id" \
                --query "SecurityGroups[*].IpPermissionsEgress[?!(IpProtocol==\`-1\` && IpRanges[?CidrIp==\`0.0.0.0/0\`])]" \
                --output text 2>/dev/null || echo "")
            if [ -n "$inbound_rules" ]; then
                default_sg_with_rules+=("$sg_id")
            fi
        fi
    done <<< "$sgs"
    
    # Report findings
    if [ ${#open_ssh[@]} -gt 0 ]; then
        local sg_list=$(printf '"%s",' "${open_ssh[@]}" | sed 's/,$//')
        add_finding "ec2" "EC2-001" "critical" \
            "SSH open to the world" \
            "${#open_ssh[@]} security group(s) allow SSH (port 22) from 0.0.0.0/0" \
            "[$sg_list]" \
            "Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager" \
            "[\"CIS 5.2\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.1\"]"
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
            "Restrict RDP access to specific IP ranges or use a bastion host" \
            "[\"CIS 5.3\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.1\"]"
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
            "Implement least privilege - only allow necessary ports from specific sources" \
            "[\"CIS 5.4\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.1\"]"
        print_finding "critical" "${#open_all[@]} security group(s) allow all traffic from anywhere"
    else
        add_pass
        print_finding "pass" "No security groups allowing all traffic from anywhere"
    fi
    
    if [ ${#default_sg_with_rules[@]} -gt 0 ]; then
        add_finding "ec2" "EC2-004" "medium" \
            "Default security groups have custom rules" \
            "${#default_sg_with_rules[@]} default security group(s) have inbound rules. Default SGs should have no rules." \
            "[]" \
            "Remove all rules from default security groups and use custom security groups instead" \
            "[\"CIS 5.4\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\"]"
        print_finding "medium" "${#default_sg_with_rules[@]} default security group(s) have rules"
    else
        add_pass
        print_finding "pass" "Default security groups have no custom rules"
    fi
    
    # Check for unencrypted EBS volumes
    print_status "  Checking EBS encryption..."
    local unencrypted_volumes=$(aws ec2 describe-volumes $PROFILE_ARG --region "$region" \
        --query "Volumes[?Encrypted==\`false\`].VolumeId" --output text 2>/dev/null || echo "")
    local unencrypted_count=$(echo "$unencrypted_volumes" | wc -w | tr -d ' ')
    
    if [ "$unencrypted_count" -gt 0 ]; then
        add_finding "ec2" "EC2-005" "high" \
            "Unencrypted EBS volumes" \
            "$unencrypted_count EBS volume(s) are not encrypted" \
            "[]" \
            "Enable EBS encryption by default and encrypt existing volumes" \
            "[\"CIS 2.2.1\",\"ISO27001 A.10.1.1\",\"SOC2 CC6.1\",\"CCSS 3.2\"]"
        print_finding "high" "$unencrypted_count unencrypted EBS volume(s)"
    else
        add_pass
        print_finding "pass" "All EBS volumes are encrypted"
    fi
    
    # Check for instances with public IPs
    print_status "  Checking public IP exposure..."
    local public_instances=$(aws ec2 describe-instances $PROFILE_ARG --region "$region" \
        --query "Reservations[*].Instances[?PublicIpAddress!=null].InstanceId" --output text 2>/dev/null || echo "")
    local public_count=$(echo "$public_instances" | wc -w | tr -d ' ')
    
    if [ "$public_count" -gt 0 ]; then
        add_finding "ec2" "EC2-006" "medium" \
            "EC2 instances with public IP addresses" \
            "$public_count instance(s) have public IP addresses" \
            "[]" \
            "Review if public IPs are necessary. Consider using NAT Gateway or private subnets" \
            "[\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\"]"
        print_finding "medium" "$public_count instance(s) with public IPs"
    else
        add_pass
        print_finding "pass" "No instances with public IPs"
    fi
    
    # Check for IMDSv1 (vulnerable to SSRF)
    print_status "  Checking IMDS configuration..."
    local imdsv1_instances=$(aws ec2 describe-instances $PROFILE_ARG --region "$region" \
        --query "Reservations[*].Instances[?MetadataOptions.HttpTokens!='required'].InstanceId" --output text 2>/dev/null || echo "")
    local imdsv1_count=$(echo "$imdsv1_instances" | wc -w | tr -d ' ')
    
    if [ "$imdsv1_count" -gt 0 ]; then
        add_finding "ec2" "EC2-007" "high" \
            "Instances allow IMDSv1" \
            "$imdsv1_count instance(s) allow IMDSv1 (vulnerable to SSRF attacks)" \
            "[]" \
            "Enforce IMDSv2 by setting HttpTokens to 'required'" \
            "[\"CIS 5.6\",\"ISO27001 A.14.2.5\",\"SOC2 CC6.1\"]"
        print_finding "high" "$imdsv1_count instance(s) allow IMDSv1"
    else
        add_pass
        print_finding "pass" "All instances enforce IMDSv2"
    fi
    
    # Check EBS snapshot public access blocking
    print_status "  Checking EBS snapshot public access block..."
    local snapshot_block=$(aws ec2 get-snapshot-block-public-access-state $PROFILE_ARG --region "$region" \
        --query 'State' --output text 2>/dev/null || echo "")
    
    if [ "$snapshot_block" != "block-all-sharing" ]; then
        add_finding "ec2" "EC2-008" "high" \
            "EBS snapshot public sharing not blocked" \
            "Account does not block public sharing of EBS snapshots. State: ${snapshot_block:-not set}" \
            "[]" \
            "Enable EBS snapshot block public access via EC2 settings or CLI" \
            "[\"CIS 2.2.2\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.1\"]"
        print_finding "high" "EBS snapshot public sharing not blocked"
    else
        add_pass
        print_finding "pass" "EBS snapshot public sharing is blocked"
    fi
    
    # Check VPC Flow Logs
    print_status "  Checking VPC Flow Logs..."
    local vpcs=$(aws ec2 describe-vpcs $PROFILE_ARG --region "$region" --query 'Vpcs[*].VpcId' --output text 2>/dev/null || echo "")
    local vpcs_without_flow_logs=()
    
    for vpc in $vpcs; do
        local flow_logs=$(aws ec2 describe-flow-logs $PROFILE_ARG --region "$region" \
            --filter "Name=resource-id,Values=$vpc" --query 'FlowLogs[0].FlowLogId' --output text 2>/dev/null || echo "")
        if [ -z "$flow_logs" ] || [ "$flow_logs" = "None" ]; then
            vpcs_without_flow_logs+=("$vpc")
        fi
    done
    
    if [ ${#vpcs_without_flow_logs[@]} -gt 0 ]; then
        add_finding "ec2" "EC2-009" "medium" \
            "VPCs without Flow Logs" \
            "${#vpcs_without_flow_logs[@]} VPC(s) do not have Flow Logs enabled" \
            "[]" \
            "Enable VPC Flow Logs for network traffic visibility and forensics" \
            "[\"CIS 3.9\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\",\"CCSS 6.1\"]"
        print_finding "medium" "${#vpcs_without_flow_logs[@]} VPC(s) without Flow Logs"
    else
        add_pass
        print_finding "pass" "All VPCs have Flow Logs enabled"
    fi
}

# ============================================================================
# RDS Checks
# ============================================================================

check_rds() {
    print_status "Checking RDS & Database Security..."
    local region=$(get_region)
    
    # Get all RDS instances
    local instances=$(aws rds describe-db-instances $PROFILE_ARG --region "$region" \
        --query 'DBInstances[*].DBInstanceIdentifier' --output text 2>/dev/null || echo "")
    
    if [ -z "$instances" ]; then
        print_status "  No RDS instances found"
        return
    fi
    
    local public_instances=()
    local unencrypted_instances=()
    local no_backup_instances=()
    local no_deletion_protection=()
    
    for instance in $instances; do
        local details=$(aws rds describe-db-instances $PROFILE_ARG --region "$region" \
            --db-instance-identifier "$instance" \
            --query 'DBInstances[0].[PubliclyAccessible,StorageEncrypted,BackupRetentionPeriod,DeletionProtection]' \
            --output text 2>/dev/null || echo "")
        
        local publicly_accessible=$(echo "$details" | awk '{print $1}')
        local encrypted=$(echo "$details" | awk '{print $2}')
        local backup_retention=$(echo "$details" | awk '{print $3}')
        local deletion_protection=$(echo "$details" | awk '{print $4}')
        
        if [ "$publicly_accessible" = "True" ]; then
            public_instances+=("$instance")
        fi
        
        if [ "$encrypted" = "False" ]; then
            unencrypted_instances+=("$instance")
        fi
        
        if [ "$backup_retention" = "0" ]; then
            no_backup_instances+=("$instance")
        fi
        
        if [ "$deletion_protection" = "False" ]; then
            no_deletion_protection+=("$instance")
        fi
    done
    
    # Report findings
    if [ ${#public_instances[@]} -gt 0 ]; then
        local instance_list=$(printf '"%s",' "${public_instances[@]}" | sed 's/,$//')
        add_finding "rds" "RDS-001" "critical" \
            "Publicly accessible RDS instances" \
            "${#public_instances[@]} RDS instance(s) are publicly accessible" \
            "[$instance_list]" \
            "Disable public accessibility and use private subnets with VPC security groups" \
            "[\"CIS 2.3.1\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 3.1\"]"
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
            "Enable encryption for RDS instances (requires snapshot and restore for existing)" \
            "[\"CIS 2.3.2\",\"ISO27001 A.10.1.1\",\"SOC2 CC6.1\",\"CCSS 3.2\"]"
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
            "Enable automated backups with at least 7 days retention" \
            "[\"CIS 2.3.3\",\"ISO27001 A.17.1.1\",\"SOC2 CC9.1\",\"CCSS 7.1\"]"
        print_finding "high" "${#no_backup_instances[@]} RDS instance(s) without backups"
    else
        add_pass
        print_finding "pass" "All RDS instances have backups enabled"
    fi
    
    if [ ${#no_deletion_protection[@]} -gt 0 ]; then
        add_finding "rds" "RDS-004" "medium" \
            "RDS instances without deletion protection" \
            "${#no_deletion_protection[@]} RDS instance(s) have deletion protection disabled" \
            "[]" \
            "Enable deletion protection for production databases" \
            "[\"ISO27001 A.17.1.1\",\"SOC2 CC9.1\"]"
        print_finding "medium" "${#no_deletion_protection[@]} RDS instance(s) without deletion protection"
    else
        add_pass
        print_finding "pass" "All RDS instances have deletion protection"
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
    local trails=$(aws cloudtrail describe-trails $PROFILE_ARG --region "$region" \
        --query 'trailList[*].Name' --output text 2>/dev/null || echo "")
    
    if [ -z "$trails" ]; then
        add_finding "logging" "LOG-001" "critical" \
            "CloudTrail not enabled" \
            "No CloudTrail trails are configured in this region" \
            "[]" \
            "Enable CloudTrail with multi-region logging and log file validation" \
            "[\"CIS 3.1\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\",\"CCSS 6.1\"]"
        print_finding "critical" "CloudTrail not enabled"
    else
        add_pass
        print_finding "pass" "CloudTrail is enabled"
        
        # Check trail configuration
        for trail in $trails; do
            local trail_config=$(aws cloudtrail describe-trails $PROFILE_ARG --region "$region" \
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
                    "Enable multi-region logging to capture API calls in all regions" \
                    "[\"CIS 3.1\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\"]"
                print_finding "high" "CloudTrail '$trail' not multi-region"
            else
                add_pass
            fi
            
            if [ "$log_validation" = "False" ]; then
                add_finding "logging" "LOG-003" "medium" \
                    "CloudTrail log validation disabled" \
                    "Trail '$trail' does not have log file validation enabled" \
                    "[\"$trail\"]" \
                    "Enable log file validation to detect tampering" \
                    "[\"CIS 3.2\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\"]"
                print_finding "medium" "CloudTrail '$trail' log validation disabled"
            else
                add_pass
            fi
            
            if [ "$kms_key" = "None" ] || [ -z "$kms_key" ]; then
                add_finding "logging" "LOG-004" "medium" \
                    "CloudTrail logs not encrypted with KMS" \
                    "Trail '$trail' logs are not encrypted with a KMS key" \
                    "[\"$trail\"]" \
                    "Enable KMS encryption for CloudTrail logs" \
                    "[\"CIS 3.7\",\"ISO27001 A.10.1.1\",\"SOC2 CC6.1\"]"
                print_finding "medium" "CloudTrail '$trail' not KMS encrypted"
            else
                add_pass
            fi
        done
    fi
    
    # Check 2: GuardDuty enabled
    print_status "  Checking GuardDuty..."
    local guardduty=$(aws guardduty list-detectors $PROFILE_ARG --region "$region" \
        --query 'DetectorIds' --output text 2>/dev/null || echo "")
    
    if [ -z "$guardduty" ]; then
        add_finding "logging" "LOG-005" "high" \
            "GuardDuty not enabled" \
            "Amazon GuardDuty is not enabled in this region" \
            "[]" \
            "Enable GuardDuty for threat detection and continuous monitoring" \
            "[\"ISO27001 A.16.1.1\",\"SOC2 CC7.2\",\"CCSS 6.2\"]"
        print_finding "high" "GuardDuty not enabled"
    else
        add_pass
        print_finding "pass" "GuardDuty is enabled"
    fi
    
    # Check 3: AWS Config enabled
    print_status "  Checking AWS Config..."
    local config_recorders=$(aws configservice describe-configuration-recorders $PROFILE_ARG --region "$region" \
        --query 'ConfigurationRecorders[*].name' --output text 2>/dev/null || echo "")
    
    if [ -z "$config_recorders" ]; then
        add_finding "logging" "LOG-006" "high" \
            "AWS Config not enabled" \
            "AWS Config is not enabled in this region" \
            "[]" \
            "Enable AWS Config to track resource configurations and changes" \
            "[\"CIS 3.5\",\"ISO27001 A.12.1.2\",\"SOC2 CC7.1\",\"CCSS 6.1\"]"
        print_finding "high" "AWS Config not enabled"
    else
        add_pass
        print_finding "pass" "AWS Config is enabled"
    fi
    
    # Check 4: Security Hub enabled
    print_status "  Checking Security Hub..."
    local security_hub=$(aws securityhub describe-hub $PROFILE_ARG --region "$region" 2>/dev/null || echo "")
    
    if [ -z "$security_hub" ]; then
        add_finding "logging" "LOG-007" "medium" \
            "Security Hub not enabled" \
            "AWS Security Hub is not enabled in this region" \
            "[]" \
            "Enable Security Hub for centralized security findings and compliance checks" \
            "[\"ISO27001 A.12.6.1\",\"SOC2 CC7.1\"]"
        print_finding "medium" "Security Hub not enabled"
    else
        add_pass
        print_finding "pass" "Security Hub is enabled"
    fi
    
    # Check 5: Access Analyzer
    print_status "  Checking IAM Access Analyzer..."
    local analyzer=$(aws accessanalyzer list-analyzers $PROFILE_ARG --region "$region" \
        --query 'analyzers[?type==`EXTERNAL`].arn' --output text 2>/dev/null || echo "")
    
    if [ -z "$analyzer" ]; then
        add_finding "logging" "LOG-008" "medium" \
            "IAM Access Analyzer not enabled" \
            "No external access analyzer is configured in this region" \
            "[]" \
            "Enable IAM Access Analyzer to identify resources shared externally" \
            "[\"CIS 1.21\",\"ISO27001 A.9.2.3\",\"SOC2 CC6.3\"]"
        print_finding "medium" "IAM Access Analyzer not enabled"
    else
        add_pass
        print_finding "pass" "IAM Access Analyzer is enabled"
    fi
}

# ============================================================================
# KMS Checks
# ============================================================================

check_kms() {
    print_status "Checking KMS & Encryption..."
    local region=$(get_region)
    
    # Get customer managed keys
    local keys=$(aws kms list-keys $PROFILE_ARG --region "$region" \
        --query 'Keys[*].KeyId' --output text 2>/dev/null || echo "")
    
    if [ -z "$keys" ]; then
        print_status "  No customer managed KMS keys found"
        return
    fi
    
    local no_rotation=()
    
    for key in $keys; do
        # Check if it's customer managed (not AWS managed)
        local key_manager=$(aws kms describe-key $PROFILE_ARG --region "$region" --key-id "$key" \
            --query 'KeyMetadata.KeyManager' --output text 2>/dev/null || echo "")
        
        if [ "$key_manager" = "CUSTOMER" ]; then
            local rotation=$(aws kms get-key-rotation-status $PROFILE_ARG --region "$region" --key-id "$key" \
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
            "Enable automatic key rotation for customer managed KMS keys" \
            "[\"CIS 3.8\",\"ISO27001 A.10.1.2\",\"SOC2 CC6.1\",\"CCSS 3.3\"]"
        print_finding "medium" "${#no_rotation[@]} KMS key(s) without rotation"
    else
        add_pass
        print_finding "pass" "All customer managed KMS keys have rotation enabled"
    fi
}

# ============================================================================
# Secrets Manager Checks
# ============================================================================

check_secrets() {
    print_status "Checking Secrets Manager..."
    local region=$(get_region)
    
    local secrets=$(aws secretsmanager list-secrets $PROFILE_ARG --region "$region" \
        --query 'SecretList[*].[Name,RotationEnabled]' --output text 2>/dev/null || echo "")
    
    if [ -z "$secrets" ]; then
        print_status "  No secrets found in Secrets Manager"
        return
    fi
    
    local no_rotation=()
    
    while IFS=$'\t' read -r name rotation; do
        if [ "$rotation" = "False" ] || [ "$rotation" = "None" ]; then
            no_rotation+=("$name")
        fi
    done <<< "$secrets"
    
    if [ ${#no_rotation[@]} -gt 0 ]; then
        add_finding "secrets" "SEC-001" "medium" \
            "Secrets without automatic rotation" \
            "${#no_rotation[@]} secret(s) do not have automatic rotation enabled" \
            "[]" \
            "Enable automatic rotation for secrets to reduce exposure risk" \
            "[\"ISO27001 A.10.1.2\",\"SOC2 CC6.1\",\"CCSS 3.3\"]"
        print_finding "medium" "${#no_rotation[@]} secret(s) without rotation"
    else
        add_pass
        print_finding "pass" "All secrets have rotation enabled"
    fi
}

# ============================================================================
# ECR Checks
# ============================================================================

check_ecr() {
    print_status "Checking ECR Container Registry..."
    local region=$(get_region)
    
    local repos=$(aws ecr describe-repositories $PROFILE_ARG --region "$region" \
        --query 'repositories[*].[repositoryName,imageScanningConfiguration.scanOnPush]' \
        --output text 2>/dev/null || echo "")
    
    if [ -z "$repos" ]; then
        print_status "  No ECR repositories found"
        return
    fi
    
    local no_scanning=()
    
    while IFS=$'\t' read -r name scan_enabled; do
        if [ "$scan_enabled" = "False" ] || [ "$scan_enabled" = "None" ]; then
            no_scanning+=("$name")
        fi
    done <<< "$repos"
    
    if [ ${#no_scanning[@]} -gt 0 ]; then
        add_finding "ecr" "ECR-001" "medium" \
            "ECR repositories without image scanning" \
            "${#no_scanning[@]} ECR repository(ies) do not have image scanning enabled" \
            "[]" \
            "Enable scan on push for all ECR repositories to detect vulnerabilities" \
            "[\"ISO27001 A.12.6.1\",\"SOC2 CC7.1\",\"CCSS 2.1\"]"
        print_finding "medium" "${#no_scanning[@]} ECR repo(s) without scanning"
    else
        add_pass
        print_finding "pass" "All ECR repositories have scanning enabled"
    fi
}

# ============================================================================
# Lambda Checks
# ============================================================================

check_lambda() {
    print_status "Checking Lambda Functions..."
    local region=$(get_region)
    
    local functions=$(aws lambda list-functions $PROFILE_ARG --region "$region" \
        --query 'Functions[*].[FunctionName,VpcConfig.VpcId,Runtime]' \
        --output text 2>/dev/null || echo "")
    
    if [ -z "$functions" ]; then
        print_status "  No Lambda functions found"
        return
    fi
    
    local deprecated_runtimes=()
    
    while IFS=$'\t' read -r name vpc_id runtime; do
        # Check for deprecated runtimes
        case "$runtime" in
            python2.7|python3.6|nodejs10.x|nodejs8.10|nodejs12.x|ruby2.5|java8|dotnetcore2.1|dotnetcore3.1)
                deprecated_runtimes+=("$name ($runtime)")
                ;;
        esac
    done <<< "$functions"
    
    if [ ${#deprecated_runtimes[@]} -gt 0 ]; then
        add_finding "lambda" "LAM-001" "medium" \
            "Lambda functions using deprecated runtimes" \
            "${#deprecated_runtimes[@]} Lambda function(s) use deprecated or end-of-support runtimes" \
            "[]" \
            "Upgrade Lambda functions to supported runtime versions" \
            "[\"ISO27001 A.14.2.2\",\"SOC2 CC7.1\"]"
        print_finding "medium" "${#deprecated_runtimes[@]} function(s) with deprecated runtimes"
    else
        add_pass
        print_finding "pass" "All Lambda functions use supported runtimes"
    fi
}

# ============================================================================
# CloudWatch Log Checks
# ============================================================================

check_cloudwatch_logs() {
    print_status "Checking CloudWatch Logs..."
    local region=$(get_region)
    
    # Check 1: Log groups without retention
    local log_groups=$(aws logs describe-log-groups $PROFILE_ARG --region "$region" \
        --query 'logGroups[?retentionInDays==`null`].logGroupName' --output text 2>/dev/null || echo "")
    
    local no_retention_count=0
    if [ -n "$log_groups" ]; then
        no_retention_count=$(echo "$log_groups" | wc -w | tr -d ' ')
    fi
    
    if [ "$no_retention_count" -gt 0 ]; then
        add_finding "cloudwatch" "CW-001" "low" \
            "CloudWatch log groups without retention" \
            "$no_retention_count log group(s) have no retention policy (logs never expire)" \
            "[]" \
            "Set retention policies on log groups to control costs and comply with data retention requirements" \
            "[\"CIS 3.1\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\"]"
        print_finding "low" "$no_retention_count log group(s) without retention"
    else
        add_pass
        print_finding "pass" "All log groups have retention policies"
    fi
    
    # Check 2: CloudTrail integration with CloudWatch Logs
    local trail_name=$(aws cloudtrail describe-trails $PROFILE_ARG --region "$region" \
        --query 'trailList[0].Name' --output text 2>/dev/null || echo "")
    
    if [ -n "$trail_name" ] && [ "$trail_name" != "None" ]; then
        local cwl_arn=$(aws cloudtrail get-trail $PROFILE_ARG --name "$trail_name" \
            --query 'Trail.CloudWatchLogsLogGroupArn' --output text 2>/dev/null || echo "")
        
        if [ -z "$cwl_arn" ] || [ "$cwl_arn" = "None" ]; then
            add_finding "cloudwatch" "CW-002" "medium" \
                "CloudTrail not integrated with CloudWatch Logs" \
                "CloudTrail is not sending logs to CloudWatch Logs for real-time monitoring" \
                "[]" \
                "Configure CloudTrail to send logs to CloudWatch Logs for metric filters and alarms" \
                "[\"CIS 3.4\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\"]"
            print_finding "medium" "CloudTrail not sending to CloudWatch Logs"
        else
            add_pass
            print_finding "pass" "CloudTrail integrated with CloudWatch Logs"
        fi
    fi
}

# ============================================================================
# CIS Alarms Check
# ============================================================================

check_cis_alarms() {
    print_status "Checking CIS CloudWatch Alarms..."
    local region=$(get_region)
    
    # Check for essential CIS alarms
    local cis_alarms=(
        "CIS-RootUserUsage"
        "CIS-UnauthorizedAPICalls"
        "CIS-ConsoleSignInWithoutMFA"
        "CIS-IAMPolicyChanges"
        "CIS-CloudTrailConfigChanges"
        "CIS-SecurityGroupChanges"
        "CIS-VPCChanges"
    )
    
    local existing_alarms=$(aws cloudwatch describe-alarms $PROFILE_ARG --region "$region" \
        --query 'MetricAlarms[].AlarmName' --output text 2>/dev/null || echo "")
    
    local missing_alarms=()
    for alarm in "${cis_alarms[@]}"; do
        if ! echo "$existing_alarms" | grep -q "$alarm"; then
            missing_alarms+=("$alarm")
        fi
    done
    
    if [ ${#missing_alarms[@]} -gt 0 ]; then
        add_finding "cloudwatch" "CW-003" "medium" \
            "CIS CloudWatch alarms not configured" \
            "${#missing_alarms[@]} of 7 essential CIS security alarms are missing" \
            "[]" \
            "Create CloudWatch metric filters and alarms for CIS benchmark security events" \
            "[\"CIS 4.1-4.14\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\"]"
        print_finding "medium" "${#missing_alarms[@]} CIS alarm(s) missing"
    else
        add_pass
        print_finding "pass" "CIS CloudWatch alarms configured"
    fi
}

# ============================================================================
# Amazon Inspector Check
# ============================================================================

check_inspector() {
    print_status "Checking Amazon Inspector..."
    local region=$(get_region)
    
    # Check if Inspector v2 is enabled
    local inspector_status=$(aws inspector2 batch-get-account-status $PROFILE_ARG --region "$region" \
        --query 'accounts[0].state.status' --output text 2>/dev/null || echo "")
    
    if [ "$inspector_status" != "ENABLED" ] && [ "$inspector_status" != "ENABLING" ]; then
        add_finding "inspector" "INS-001" "medium" \
            "Amazon Inspector not enabled" \
            "Amazon Inspector v2 is not enabled for vulnerability scanning" \
            "[]" \
            "Enable Amazon Inspector for EC2, ECR, and Lambda vulnerability scanning" \
            "[\"ISO27001 A.12.6.1\",\"SOC2 CC7.1\",\"CCSS 5.1\"]"
        print_finding "medium" "Amazon Inspector not enabled"
    else
        add_pass
        print_finding "pass" "Amazon Inspector is enabled"
    fi
}

# ============================================================================
# AWS Backup Check
# ============================================================================

check_backup() {
    print_status "Checking AWS Backup..."
    local region=$(get_region)
    
    # Check for backup plans
    local backup_plans=$(aws backup list-backup-plans $PROFILE_ARG --region "$region" \
        --query 'BackupPlansList[].BackupPlanName' --output text 2>/dev/null || echo "")
    
    if [ -z "$backup_plans" ]; then
        add_finding "backup" "BAK-001" "medium" \
            "No AWS Backup plans configured" \
            "No backup plans are configured in this region for automated backups" \
            "[]" \
            "Create AWS Backup plans to automate backups of critical resources" \
            "[\"ISO27001 A.17.1.1\",\"SOC2 CC9.1\",\"CCSS 7.1\"]"
        print_finding "medium" "No AWS Backup plans found"
    else
        add_pass
        print_finding "pass" "AWS Backup plans configured"
    fi
}

# ============================================================================
# ACM Certificate Check
# ============================================================================

check_acm() {
    print_status "Checking ACM Certificates..."
    local region=$(get_region)
    
    local certs=$(aws acm list-certificates $PROFILE_ARG --region "$region" \
        --query 'CertificateSummaryList[*].[CertificateArn,DomainName]' --output text 2>/dev/null || echo "")
    
    if [ -z "$certs" ]; then
        print_status "  No ACM certificates found"
        return
    fi
    
    local expiring_soon=()
    local now=$(date +%s)
    local thirty_days=$((30 * 24 * 60 * 60))
    
    while IFS=$'\t' read -r arn domain; do
        local expires=$(aws acm describe-certificate $PROFILE_ARG --region "$region" \
            --certificate-arn "$arn" \
            --query 'Certificate.NotAfter' --output text 2>/dev/null || echo "")
        
        if [ -n "$expires" ] && [ "$expires" != "None" ]; then
            local expires_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%S" "${expires%+*}" +%s 2>/dev/null || \
                                  date -d "$expires" +%s 2>/dev/null || echo "0")
            local diff=$((expires_epoch - now))
            
            if [ "$diff" -lt "$thirty_days" ] && [ "$diff" -gt 0 ]; then
                expiring_soon+=("$domain")
            fi
        fi
    done <<< "$certs"
    
    if [ ${#expiring_soon[@]} -gt 0 ]; then
        add_finding "acm" "ACM-001" "high" \
            "ACM certificates expiring soon" \
            "${#expiring_soon[@]} certificate(s) will expire within 30 days" \
            "[]" \
            "Renew or replace expiring certificates before they expire" \
            "[\"ISO27001 A.10.1.2\",\"SOC2 CC6.1\"]"
        print_finding "high" "${#expiring_soon[@]} certificate(s) expiring within 30 days"
    else
        add_pass
        print_finding "pass" "No certificates expiring within 30 days"
    fi
}

# ============================================================================
# EBS Default Encryption Check
# ============================================================================

check_ebs_default_encryption() {
    print_status "Checking EBS Default Encryption..."
    local region=$(get_region)
    
    local default_encryption=$(aws ec2 get-ebs-encryption-by-default $PROFILE_ARG --region "$region" \
        --query 'EbsEncryptionByDefault' --output text 2>/dev/null || echo "")
    
    if [ "$default_encryption" != "True" ]; then
        add_finding "ec2" "EC2-010" "medium" \
            "EBS default encryption not enabled" \
            "Default EBS encryption is not enabled for new volumes in this region" \
            "[]" \
            "Enable EBS encryption by default to ensure all new volumes are encrypted" \
            "[\"CIS 2.2.1\",\"ISO27001 A.10.1.1\",\"SOC2 CC6.1\",\"CCSS 4.2\"]"
        print_finding "medium" "EBS default encryption not enabled"
    else
        add_pass
        print_finding "pass" "EBS default encryption is enabled"
    fi
}

# ============================================================================
# SSM Public Sharing Block Check
# ============================================================================

check_ssm_sharing() {
    print_status "Checking SSM Document Sharing..."
    local region=$(get_region)
    
    local public_docs=$(aws ssm list-documents $PROFILE_ARG --region "$region" \
        --filters "Key=Owner,Values=Self" \
        --query 'DocumentIdentifiers[?contains(Permissions,`All`)].Name' --output text 2>/dev/null || echo "")
    
    if [ -n "$public_docs" ]; then
        local doc_count=$(echo "$public_docs" | wc -w | tr -d ' ')
        add_finding "ssm" "SSM-001" "high" \
            "SSM documents shared publicly" \
            "$doc_count SSM document(s) are shared publicly" \
            "[]" \
            "Remove public sharing from SSM documents or enable account-level block" \
            "[\"CIS 2.3.3\",\"ISO27001 A.9.4.1\",\"SOC2 CC6.1\"]"
        print_finding "high" "$doc_count SSM document(s) shared publicly"
    else
        add_pass
        print_finding "pass" "No publicly shared SSM documents"
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
  "account_id": "$ACCOUNT_ID",
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
  "compliance_coverage": {
    "cis_aws_foundations": true,
    "iso_27001": true,
    "soc_2": true,
    "ccss": true
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
    local total=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT + PASS_COUNT))
    
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
    echo "  Total checks: $total"
    echo ""
    echo -e "  Compliance frameworks covered:"
    echo "    • CIS AWS Foundations Benchmark"
    echo "    • ISO 27001"
    echo "    • SOC 2"
    echo "    • CCSS (Cryptocurrency Security Standard)"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Report saved to: ${GREEN}$OUTPUT_FILE${NC}"
    echo ""
    echo "  View results:"
    echo "    cat $OUTPUT_FILE | jq '.'"
    echo "    cat $OUTPUT_FILE | jq '.findings[]'"
    echo ""
    echo "  Next steps:"
    echo "    1. Review the report for sensitive information"
    echo "    2. Share at: https://scamshield.app/audit"
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
            -p|--profile)
                PROFILE="$2"
                shift 2
                ;;
            -r|--region)
                REGION="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -a|--all-regions)
                ALL_REGIONS=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
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
    echo ""
    check_secrets
    echo ""
    check_ecr
    echo ""
    check_lambda
    check_cloudwatch_logs
    check_cis_alarms
    check_inspector
    check_backup
    check_acm
    check_ebs_default_encryption
    check_ssm_sharing
    
    # Generate report
    generate_report
    
    # Print summary
    print_summary
}

main "$@"
