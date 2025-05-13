#!/usr/bin/env python3
"""
AWS S3 Security Audit Script
----------------------------
This script analyzes all S3 buckets for security best practices and generates a colored report in the terminal.
The analysis includes:
- Public access settings
- Encryption
- Versioning policies
- Access logging
- Retention policies
- Access control
- CORS security
- Object lifecycle policies

Requirements:
- AWS CLI configured with appropriate permissions
- Python 3.6+
- Libraries: boto3, tabulate, colorama
"""

import boto3
import json
import sys
import datetime
from botocore.exceptions import ClientError
from tabulate import tabulate
from colorama import init, Fore, Back, Style

# Initialize colors
init(autoreset=True)

# Global settings
VERBOSE = False

def print_verbose(message):
    """Print message only in verbose mode"""
    if VERBOSE:
        print(f"{Fore.CYAN}[INFO] {message}{Style.RESET_ALL}")

def get_aws_account_id():
    """Get AWS account ID"""
    try:
        sts_client = boto3.client('sts')
        return sts_client.get_caller_identity()["Account"]
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Cannot retrieve AWS account ID: {e}{Style.RESET_ALL}")
        return "Unknown"

def check_s3_bucket_public_access(s3_client, bucket_name):
    """Check if bucket has public access"""
    try:
        # Check public access block
        public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
        block_config = public_access_block['PublicAccessBlockConfiguration']
        
        is_public = not (
            block_config.get('BlockPublicAcls', False) and
            block_config.get('BlockPublicPolicy', False) and
            block_config.get('IgnorePublicAcls', False) and
            block_config.get('RestrictPublicBuckets', False)
        )
        
        return {
            'is_public': is_public,
            'block_public_acls': block_config.get('BlockPublicAcls', False),
            'block_public_policy': block_config.get('BlockPublicPolicy', False),
            'ignore_public_acls': block_config.get('IgnorePublicAcls', False),
            'restrict_public_buckets': block_config.get('RestrictPublicBuckets', False)
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
            return {
                'is_public': True,
                'block_public_acls': False,
                'block_public_policy': False,
                'ignore_public_acls': False,
                'restrict_public_buckets': False
            }
        print(f"{Fore.YELLOW}[WARNING] Cannot check public access for bucket {bucket_name}: {e}{Style.RESET_ALL}")
        return {
            'is_public': "Unknown",
            'block_public_acls': "Unknown",
            'block_public_policy': "Unknown",
            'ignore_public_acls': "Unknown",
            'restrict_public_buckets': "Unknown"
        }

def check_s3_bucket_encryption(s3_client, bucket_name):
    """Check bucket encryption"""
    try:
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rules = encryption['ServerSideEncryptionConfiguration']['Rules']
        
        encryption_type = None
        kms_key_id = None
        
        for rule in rules:
            if 'ApplyServerSideEncryptionByDefault' in rule:
                default_encryption = rule['ApplyServerSideEncryptionByDefault']
                encryption_type = default_encryption.get('SSEAlgorithm')
                if 'KMSMasterKeyID' in default_encryption:
                    kms_key_id = default_encryption['KMSMasterKeyID']
        
        return {
            'is_encrypted': True,
            'encryption_type': encryption_type,
            'kms_key_id': kms_key_id
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
            return {
                'is_encrypted': False,
                'encryption_type': None,
                'kms_key_id': None
            }
        print(f"{Fore.YELLOW}[WARNING] Cannot check encryption for bucket {bucket_name}: {e}{Style.RESET_ALL}")
        return {
            'is_encrypted': "Unknown",
            'encryption_type': None,
            'kms_key_id': None
        }

def check_s3_bucket_versioning(s3_client, bucket_name):
    """Check bucket versioning"""
    try:
        versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = versioning.get('Status', 'Disabled')
        mfa_delete = versioning.get('MFADelete', 'Disabled')
        
        return {
            'versioning_enabled': status == 'Enabled',
            'status': status,
            'mfa_delete': mfa_delete
        }
    except ClientError as e:
        print(f"{Fore.YELLOW}[WARNING] Cannot check versioning for bucket {bucket_name}: {e}{Style.RESET_ALL}")
        return {
            'versioning_enabled': "Unknown",
            'status': "Unknown",
            'mfa_delete': "Unknown"
        }

def check_s3_bucket_logging(s3_client, bucket_name):
    """Check bucket logging"""
    try:
        logging = s3_client.get_bucket_logging(Bucket=bucket_name)
        
        if 'LoggingEnabled' in logging:
            target_bucket = logging['LoggingEnabled'].get('TargetBucket')
            target_prefix = logging['LoggingEnabled'].get('TargetPrefix')
            return {
                'logging_enabled': True,
                'target_bucket': target_bucket,
                'target_prefix': target_prefix
            }
        else:
            return {
                'logging_enabled': False,
                'target_bucket': None,
                'target_prefix': None
            }
    except ClientError as e:
        print(f"{Fore.YELLOW}[WARNING] Cannot check logging for bucket {bucket_name}: {e}{Style.RESET_ALL}")
        return {
            'logging_enabled': "Unknown",
            'target_bucket': None,
            'target_prefix': None
        }

def check_s3_bucket_policy(s3_client, bucket_name):
    """Check bucket policy"""
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_json = json.loads(policy['Policy'])
        
        # Analyze policy for security
        has_public_access = False
        has_secure_transport = False
        has_wildcard_principal = False  # Nowa flaga
        
        for statement in policy_json.get('Statement', []):
            principal = statement.get('Principal', {})
            effect = statement.get('Effect', '')
            
            # Check for public access
            if principal == '*' or principal.get('AWS') == '*' and effect == 'Allow':
                has_public_access = True
            
            # Check for wildcard principal (new)
            if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                has_wildcard_principal = True
            elif isinstance(principal, dict) and isinstance(principal.get('AWS'), list):
                for aws_principal in principal.get('AWS'):
                    if aws_principal == '*':
                        has_wildcard_principal = True
                        break
            
            # Check for secure transport requirement
            if effect == 'Deny' and 'Condition' in statement:
                condition = statement.get('Condition', {})
                if 'Bool' in condition and 'aws:SecureTransport' in condition['Bool']:
                    if not condition['Bool']['aws:SecureTransport']:
                        has_secure_transport = True
        
        return {
            'has_policy': True,
            'has_public_access': has_public_access,
            'has_secure_transport': has_secure_transport,
            'has_wildcard_principal': has_wildcard_principal,  # Nowe pole
            'policy': policy_json
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
            return {
                'has_policy': False,
                'has_public_access': False,
                'has_secure_transport': False,
                'has_wildcard_principal': False,  # Nowe pole
                'policy': None
            }
        print(f"{Fore.YELLOW}[WARNING] Cannot retrieve policy for bucket {bucket_name}: {e}{Style.RESET_ALL}")
        return {
            'has_policy': "Unknown",
            'has_public_access': "Unknown",
            'has_secure_transport': "Unknown",
            'has_wildcard_principal': "Unknown",  # Nowe pole
            'policy': None
        }

def check_s3_bucket_lifecycle(s3_client, bucket_name):
    """Check bucket lifecycle policy"""
    try:
        lifecycle = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        rules = lifecycle.get('Rules', [])
        
        has_expiration = False
        has_transition = False
        
        for rule in rules:
            if rule.get('Status') == 'Enabled':
                if 'Expiration' in rule:
                    has_expiration = True
                if 'Transitions' in rule:
                    has_transition = True
        
        return {
            'has_lifecycle': True,
            'has_expiration': has_expiration,
            'has_transition': has_transition,
            'rules_count': len(rules)
        }
    except ClientError as e:
        if e.response['Error']['Code'] in ['NoSuchLifecycleConfiguration', 'LifecycleConfigurationNotFoundError']:
            return {
                'has_lifecycle': False,
                'has_expiration': False,
                'has_transition': False,
                'rules_count': 0
            }
        print(f"{Fore.YELLOW}[WARNING] Cannot retrieve lifecycle configuration for bucket {bucket_name}: {e}{Style.RESET_ALL}")
        return {
            'has_lifecycle': "Unknown",
            'has_expiration': "Unknown",
            'has_transition': "Unknown",
            'rules_count': "Unknown"
        }

def check_s3_bucket_cors(s3_client, bucket_name):
    """Check bucket CORS configuration"""
    try:
        cors = s3_client.get_bucket_cors(Bucket=bucket_name)
        cors_rules = cors.get('CORSRules', [])
        
        has_wildcard_origin = False
        for rule in cors_rules:
            if '*' in rule.get('AllowedOrigins', []):
                has_wildcard_origin = True
                break
        
        return {
            'has_cors': True,
            'has_wildcard_origin': has_wildcard_origin,
            'rules_count': len(cors_rules)
        }
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchCORSConfiguration':
            return {
                'has_cors': False,
                'has_wildcard_origin': False,
                'rules_count': 0
            }
        print(f"{Fore.YELLOW}[WARNING] Cannot retrieve CORS configuration for bucket {bucket_name}: {e}{Style.RESET_ALL}")
        return {
            'has_cors': "Unknown",
            'has_wildcard_origin': "Unknown",
            'rules_count': "Unknown"
        }

def check_s3_bucket_object_lock(s3_client, bucket_name):
    """Check bucket Object Lock configuration"""
    try:
        object_lock = s3_client.get_object_lock_configuration(Bucket=bucket_name)
        object_lock_enabled = 'ObjectLockConfiguration' in object_lock and 'ObjectLockEnabled' in object_lock['ObjectLockConfiguration']
        
        if object_lock_enabled:
            return {
                'object_lock_enabled': object_lock['ObjectLockConfiguration']['ObjectLockEnabled'] == 'Enabled',
                'retention_mode': object_lock.get('ObjectLockConfiguration', {}).get('Rule', {}).get('DefaultRetention', {}).get('Mode'),
                'retention_days': object_lock.get('ObjectLockConfiguration', {}).get('Rule', {}).get('DefaultRetention', {}).get('Days')
            }
        else:
            return {
                'object_lock_enabled': False,
                'retention_mode': None,
                'retention_days': None
            }
    except ClientError as e:
        if e.response['Error']['Code'] == 'ObjectLockConfigurationNotFoundError':
            return {
                'object_lock_enabled': False,
                'retention_mode': None,
                'retention_days': None
            }
        print(f"{Fore.YELLOW}[WARNING] Cannot retrieve Object Lock configuration for bucket {bucket_name}: {e}{Style.RESET_ALL}")
        return {
            'object_lock_enabled': "Unknown",
            'retention_mode': None,
            'retention_days': None
        }

def calculate_security_score(bucket_info):
    """Calculate security score for bucket (from 0 to 100)"""
    score = 0
    total = 0
    
    # Check public access block (20 points)
    if bucket_info['public_access'] and bucket_info['public_access']['is_public'] is not True:
        score += 20
    total += 20
    
    # Check encryption (15 points)
    if bucket_info['encryption'] and bucket_info['encryption']['is_encrypted'] is True:
        score += 15
    total += 15
    
    # Check versioning (10 points)
    if bucket_info['versioning'] and bucket_info['versioning']['versioning_enabled'] is True:
        score += 10
    total += 10
    
    # Check logging (10 points)
    if bucket_info['logging'] and bucket_info['logging']['logging_enabled'] is True:
        score += 10
    total += 10
    
    # Check policy (15 points)
    if bucket_info['policy']:
        policy_score = 15
        if bucket_info['policy']['has_public_access'] is True:
            policy_score -= 10
        if bucket_info['policy']['has_secure_transport'] is True:
            policy_score += 5
        score += max(0, policy_score)
    total += 15
    
    # Check lifecycle (10 points)
    if bucket_info['lifecycle'] and bucket_info['lifecycle']['has_lifecycle'] is True:
        lifecycle_score = 5
        if bucket_info['lifecycle']['has_expiration'] is True:
            lifecycle_score += 2.5
        if bucket_info['lifecycle']['has_transition'] is True:
            lifecycle_score += 2.5
        score += lifecycle_score
    total += 10
    
    # Check CORS (10 points)
    if bucket_info['cors']:
        cors_score = 10
        if bucket_info['cors']['has_cors'] is True and bucket_info['cors']['has_wildcard_origin'] is True:
            cors_score -= 5
        score += cors_score
    total += 10
    
    # Check Object Lock (10 points)
    if bucket_info['public_access'] and bucket_info['public_access']['is_public'] is not True:
        score += 15
    total += 15
    
    # Check ACL (5 points) - Nowe sprawdzenie
    if bucket_info['acl'] and bucket_info['acl']['has_public_acl'] is not True:
        score += 5
    total += 5

    if bucket_info['policy']:
        policy_score = 15
        if bucket_info['policy']['has_public_access'] is True:
            policy_score -= 5
        if bucket_info['policy']['has_wildcard_principal'] is True:
            policy_score -= 5
        if bucket_info['policy']['has_secure_transport'] is True:
            policy_score += 5
        score += max(0, policy_score)
    total += 15
    
    # Calculate on scale 0-100
    if total > 0:
        final_score = (score / total) * 100
    else:
        final_score = 0
    
    return round(final_score, 1)

def get_security_level(score):
    """Return security level based on score"""
    if score >= 90:
        return f"{Fore.GREEN}Very Good{Style.RESET_ALL}"
    elif score >= 75:
        return f"{Fore.LIGHTGREEN_EX}Good{Style.RESET_ALL}"
    elif score >= 60:
        return f"{Fore.YELLOW}Moderate{Style.RESET_ALL}"
    elif score >= 40:
        return f"{Fore.LIGHTYELLOW_EX}Poor{Style.RESET_ALL}"
    else:
        return f"{Fore.RED}Critical{Style.RESET_ALL}"

def analyze_s3_bucket(s3_client, bucket_name):
    """Analyze S3 bucket for all security aspects"""
    print_verbose(f"Analyzing bucket: {bucket_name}")
    
    bucket_info = {
        'name': bucket_name,
        'public_access': check_s3_bucket_public_access(s3_client, bucket_name),
        'acl': check_s3_bucket_acl(s3_client, bucket_name), 
        'encryption': check_s3_bucket_encryption(s3_client, bucket_name),
        'versioning': check_s3_bucket_versioning(s3_client, bucket_name),
        'logging': check_s3_bucket_logging(s3_client, bucket_name),
        'policy': check_s3_bucket_policy(s3_client, bucket_name),
        'lifecycle': check_s3_bucket_lifecycle(s3_client, bucket_name),
        'cors': check_s3_bucket_cors(s3_client, bucket_name),
        'object_lock': check_s3_bucket_object_lock(s3_client, bucket_name)
    }
    
    # Calculate security score
    bucket_info['security_score'] = calculate_security_score(bucket_info)
    bucket_info['security_level'] = get_security_level(bucket_info['security_score'])
    
    return bucket_info

def format_value(value, positive_state=True):
    """Format values for table with appropriate color"""
    if isinstance(value, bool):
        if value is True:
            return f"{Fore.GREEN if positive_state else Fore.RED}Yes{Style.RESET_ALL}"
        else:
            return f"{Fore.RED if positive_state else Fore.GREEN}No{Style.RESET_ALL}"
    elif value == "Unknown":
        return f"{Fore.YELLOW}Unknown{Style.RESET_ALL}"
    return value

def generate_summary_table(buckets_info):
    """Generate summary table for buckets"""
    headers = ["Bucket", "Score", "Level", "Public", "Public ACL", "Wildcard Principal", "Encryption", "Versioning", "Logging", "Policy", "Lifecycle"]
    rows = []
    
    for bucket in buckets_info:
        rows.append([
            bucket['name'],
            f"{Fore.CYAN}{bucket['security_score']}/100{Style.RESET_ALL}",
            bucket['security_level'],
            format_value(bucket['public_access']['is_public'], False),
            format_value(bucket['acl']['has_public_acl'], False),
            format_value(bucket['policy']['has_wildcard_principal'], False),  # Nowa kolumna
            format_value(bucket['encryption']['is_encrypted']),
            format_value(bucket['versioning']['versioning_enabled']),
            format_value(bucket['logging']['logging_enabled']),
            format_value(bucket['policy']['has_policy']),
            format_value(bucket['lifecycle']['has_lifecycle'])
        ])
    
    return tabulate(rows, headers=headers, tablefmt="pretty")

def generate_detailed_report(bucket_info):
    """Generate detailed report for bucket"""
    report = [
        f"{Fore.CYAN}============================================={Style.RESET_ALL}",
        f"{Fore.CYAN}     DETAILED SECURITY REPORT FOR BUCKET     {Style.RESET_ALL}",
        f"{Fore.CYAN}============================================={Style.RESET_ALL}",
        f"Bucket name: {Fore.BLUE}{bucket_info['name']}{Style.RESET_ALL}",
        f"Security score: {Fore.CYAN}{bucket_info['security_score']}/100{Style.RESET_ALL}",
        f"Security level: {bucket_info['security_level']}",
        "",
        f"{Fore.CYAN}1. PUBLIC ACCESS CONTROL{Style.RESET_ALL}",
        f"Public access: {format_value(bucket_info['public_access']['is_public'], False)}",
        f"BlockPublicAcls: {format_value(bucket_info['public_access']['block_public_acls'])}",
        f"BlockPublicPolicy: {format_value(bucket_info['public_access']['block_public_policy'])}",
        f"IgnorePublicAcls: {format_value(bucket_info['public_access']['ignore_public_acls'])}",
        f"RestrictPublicBuckets: {format_value(bucket_info['public_access']['restrict_public_buckets'])}",
        "",
        f"{Fore.CYAN}1.1. BUCKET ACL{Style.RESET_ALL}",
        f"Public ACL grants: {format_value(bucket_info['acl']['has_public_acl'], False)}",
    ]
    
    if bucket_info['acl']['has_public_acl'] is True:
        report.append(f"Public permissions: {', '.join(bucket_info['acl']['public_permissions'])}")
  
    
    if bucket_info['encryption']['is_encrypted'] is True:
        report.extend([
            f"Encryption type: {bucket_info['encryption']['encryption_type']}",
            f"KMS Key ID: {bucket_info['encryption']['kms_key_id'] if bucket_info['encryption']['kms_key_id'] else 'N/A'}"
        ])
    
    report.extend([
        "",
        f"{Fore.CYAN}3. VERSIONING{Style.RESET_ALL}",
        f"Versioning enabled: {format_value(bucket_info['versioning']['versioning_enabled'])}",
        f"Versioning status: {bucket_info['versioning']['status']}",
        f"MFA Delete: {bucket_info['versioning']['mfa_delete']}",
        "",
        f"{Fore.CYAN}4. LOGGING{Style.RESET_ALL}",
        f"Logging enabled: {format_value(bucket_info['logging']['logging_enabled'])}"
    ])
    
    if bucket_info['logging']['logging_enabled'] is True:
        report.extend([
            f"Target Bucket: {bucket_info['logging']['target_bucket']}",
            f"Target Prefix: {bucket_info['logging']['target_prefix']}"
        ])
    
    report.extend([
        "",
        f"{Fore.CYAN}5. BUCKET POLICY{Style.RESET_ALL}",
        f"Policy defined: {format_value(bucket_info['policy']['has_policy'])}"
    ])
    
    if bucket_info['policy']['has_policy'] is True:
        report.extend([
            f"Contains public access: {format_value(bucket_info['policy']['has_public_access'], False)}",
            f"Contains wildcard principal (*): {format_value(bucket_info['policy']['has_wildcard_principal'], False)}", 
            f"Requires secure transport: {format_value(bucket_info['policy']['has_secure_transport'])}"
        ])
    
    report.extend([
        "",
        f"{Fore.CYAN}6. LIFECYCLE POLICY{Style.RESET_ALL}",
        f"Lifecycle policy defined: {format_value(bucket_info['lifecycle']['has_lifecycle'])}"
    ])
    
    if bucket_info['lifecycle']['has_lifecycle'] is True:
        report.extend([
            f"Contains expiration rules: {format_value(bucket_info['lifecycle']['has_expiration'])}",
            f"Contains transition rules: {format_value(bucket_info['lifecycle']['has_transition'])}",
            f"Number of rules: {bucket_info['lifecycle']['rules_count']}"
        ])
    
    report.extend([
        "",
        f"{Fore.CYAN}7. CORS CONFIGURATION{Style.RESET_ALL}",
        f"CORS defined: {format_value(bucket_info['cors']['has_cors'])}"
    ])
    
    if bucket_info['cors']['has_cors'] is True:
        report.extend([
            f"Contains wildcard origin (*): {format_value(bucket_info['cors']['has_wildcard_origin'], False)}",
            f"Number of CORS rules: {bucket_info['cors']['rules_count']}"
        ])
    
    report.extend([
        "",
        f"{Fore.CYAN}8. OBJECT LOCK{Style.RESET_ALL}",
        f"Object Lock enabled: {format_value(bucket_info['object_lock']['object_lock_enabled'])}"
    ])
    
    if bucket_info['object_lock']['object_lock_enabled'] is True:
        report.extend([
            f"Retention mode: {bucket_info['object_lock']['retention_mode']}",
            f"Retention days: {bucket_info['object_lock']['retention_days']}"
        ])
    
    report.extend([
        "",
        f"{Fore.CYAN}9. RECOMMENDATIONS{Style.RESET_ALL}"
    ])
    
    # Generate recommendations
    recommendations = []
    
    if bucket_info['public_access']['is_public'] is True:
        recommendations.append("- Enable block public access for the bucket")
    
    if bucket_info['encryption']['is_encrypted'] is not True:
        recommendations.append("- Enable default encryption")
    
    if bucket_info['versioning']['versioning_enabled'] is not True:
        recommendations.append("- Enable object versioning")
    
    if bucket_info['logging']['logging_enabled'] is not True:
        recommendations.append("- Enable access logging")
    
    if bucket_info['policy']['has_policy'] is not True:
        recommendations.append("- Define a bucket policy with secure transport requirement")
    elif bucket_info['policy']['has_public_access'] is True:
        recommendations.append("- Remove public access from bucket policy")
    elif bucket_info['policy']['has_secure_transport'] is not True:
        recommendations.append("- Add secure transport requirement to bucket policy")
    
    if bucket_info['lifecycle']['has_lifecycle'] is not True:
        recommendations.append("- Define object lifecycle policy")
    
    if bucket_info['cors']['has_cors'] is True and bucket_info['cors']['has_wildcard_origin'] is True:
        recommendations.append("- Restrict wildcard origin (*) in CORS configuration")
    
    if not recommendations:
        recommendations.append("✅ No recommendations - bucket meets all checked security requirements")
    
    report.extend(recommendations)
    
    return "\n".join(report)

def prepare_json_output(buckets_info):
    """Prepare data for JSON export without colorama formatting"""
    json_data = {
        "report_date": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "aws_account_id": get_aws_account_id(),
        "buckets": []
    }
    
    for bucket in buckets_info:
        # Create a copy of the bucket info
        bucket_data = {
            "name": bucket["name"],
            "security_score": bucket["security_score"],
            "security_level": get_security_level_plain(bucket["security_score"]),
            "public_access": bucket["public_access"],
            "encryption": bucket["encryption"],
            "versioning": bucket["versioning"],
            "logging": bucket["logging"],
            "policy": {
                "has_policy": bucket["policy"]["has_policy"],
                "has_public_access": bucket["policy"]["has_public_access"],
                "has_wildcard_principal": bucket["policy"]["has_wildcard_principal"],  
                "has_secure_transport": bucket["policy"]["has_secure_transport"]
            },
            "lifecycle": bucket["lifecycle"],
            "cors": bucket["cors"],
            "object_lock": bucket["object_lock"],
            "recommendations": get_recommendations_for_bucket(bucket)
        }
        
        json_data["buckets"].append(bucket_data)
    
    # Add overall statistics
    total_score = sum(b['security_score'] for b in buckets_info)
    avg_score = total_score / len(buckets_info) if buckets_info else 0
    
    secure_count = len([b for b in buckets_info if b['security_score'] >= 75])
    moderate_count = len([b for b in buckets_info if 60 <= b['security_score'] < 75])
    critical_count = len([b for b in buckets_info if b['security_score'] < 60])
    
    json_data["statistics"] = {
        "total_buckets": len(buckets_info),
        "average_score": round(avg_score, 1),
        "secure_buckets": secure_count,
        "moderate_buckets": moderate_count,
        "critical_buckets": critical_count,
        "secure_percentage": round(secure_count/len(buckets_info)*100 if buckets_info else 0, 1),
        "moderate_percentage": round(moderate_count/len(buckets_info)*100 if buckets_info else 0, 1),
        "critical_percentage": round(critical_count/len(buckets_info)*100 if buckets_info else 0, 1)
    }
    
    # Add common issues
    no_encryption = len([b for b in buckets_info if b['encryption']['is_encrypted'] is not True])
    no_versioning = len([b for b in buckets_info if b['versioning']['versioning_enabled'] is not True])
    no_logging = len([b for b in buckets_info if b['logging']['logging_enabled'] is not True])
    public_access = len([b for b in buckets_info if b['public_access']['is_public'] is True])
    no_lifecycle = len([b for b in buckets_info if b['lifecycle']['has_lifecycle'] is not True])
    has_wildcard_principal = len([b for b in buckets_info if b['policy']['has_wildcard_principal'] is True]) 
    
    json_data["common_issues"] = {
        "no_encryption": {
            "count": no_encryption,
            "percentage": round(no_encryption/len(buckets_info)*100 if buckets_info else 0, 1)
        },
        "no_versioning": {
            "count": no_versioning,
            "percentage": round(no_versioning/len(buckets_info)*100 if buckets_info else 0, 1)
        },
        "no_logging": {
            "count": no_logging,
            "percentage": round(no_logging/len(buckets_info)*100 if buckets_info else 0, 1)
        },
        "public_access": {
            "count": public_access,
            "percentage": round(public_access/len(buckets_info)*100 if buckets_info else 0, 1)
        },
        "no_lifecycle": {
            "count": no_lifecycle,
            "percentage": round(no_lifecycle/len(buckets_info)*100 if buckets_info else 0, 1)
        },
         "has_wildcard_principal": { 
            "count": has_wildcard_principal,
            "percentage": round(has_wildcard_principal/len(buckets_info)*100 if buckets_info else 0, 1)
        }
    }
    
    return json_data

def get_security_level_plain(score):
    """Return security level without colorama formatting"""
    if score >= 90:
        return "Very Good"
    elif score >= 75:
        return "Good"
    elif score >= 60:
        return "Moderate"
    elif score >= 40:
        return "Poor"
    else:
        return "Critical"

def get_recommendations_for_bucket(bucket_info):
    """Get recommendations for a bucket"""
    recommendations = []
    
    if bucket_info['public_access']['is_public'] is True:
        recommendations.append("Enable block public access for the bucket")
    
    if bucket_info['acl']['has_public_acl'] is True:
        recommendations.append("Remove public access grants from bucket ACL")
    
    if bucket_info['policy']['has_policy'] is True and bucket_info['policy']['has_wildcard_principal'] is True:
        recommendations.append("Remove wildcard principal (*) from bucket policy and use specific principals")

    if bucket_info['encryption']['is_encrypted'] is not True:
        recommendations.append("Enable default encryption")
    
    if bucket_info['versioning']['versioning_enabled'] is not True:
        recommendations.append("Enable object versioning")
    
    if bucket_info['logging']['logging_enabled'] is not True:
        recommendations.append("Enable access logging")
    
    if bucket_info['policy']['has_policy'] is not True:
        recommendations.append("Define a bucket policy with secure transport requirement")
    elif bucket_info['policy']['has_public_access'] is True:
        recommendations.append("Remove public access from bucket policy")
    elif bucket_info['policy']['has_secure_transport'] is not True:
        recommendations.append("Add secure transport requirement to bucket policy")
    
    if bucket_info['lifecycle']['has_lifecycle'] is not True:
        recommendations.append("Define object lifecycle policy")
    
    if bucket_info['cors']['has_cors'] is True and bucket_info['cors']['has_wildcard_origin'] is True:
        recommendations.append("Restrict wildcard origin (*) in CORS configuration")
    
    return recommendations


def check_s3_bucket_acl(s3_client, bucket_name):
    """Check if bucket ACL grants permissions to Everyone"""
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        
        # Check if any grant gives permission to Everyone
        has_public_acl = False
        public_permissions = []
        
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            permission = grant.get('Permission', '')
            
            # Check if grantee is the "Everyone" group (AllUsers)
            if grantee.get('Type') == 'Group' and grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                has_public_acl = True
                public_permissions.append(permission)
            
        return {
            'has_public_acl': has_public_acl,
            'public_permissions': public_permissions if has_public_acl else []
        }
    
    except ClientError as e:
        print(f"{Fore.YELLOW}[WARNING] Cannot check ACL for bucket {bucket_name}: {e}{Style.RESET_ALL}")
        return {
            'has_public_acl': "Unknown",
            'public_permissions': []
        }
        
def main():
    global VERBOSE
    
    # Handle arguments
    if "--verbose" in sys.argv or "-v" in sys.argv:
        VERBOSE = True
    
    print(f"{Fore.CYAN}========================================================{Style.RESET_ALL}")
    print(f"{Fore.CYAN}            AWS S3 BUCKETS SECURITY AUDIT            {Style.RESET_ALL}")
    print(f"{Fore.CYAN}========================================================{Style.RESET_ALL}")
    print(f"Report generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"AWS Account ID: {get_aws_account_id()}")
    print(f"{Fore.CYAN}========================================================{Style.RESET_ALL}")
    print("")
    
    try:
        # Create boto3 session and client
        session = boto3.Session()
        s3_client = session.client('s3')
        
        # Get list of buckets
        response = s3_client.list_buckets()
        buckets = response['Buckets']
        
        if not buckets:
            print(f"{Fore.YELLOW}No S3 buckets found in this AWS account.{Style.RESET_ALL}")
            return
        
        print(f"Found {len(buckets)} S3 buckets. Starting analysis...\n")
        
        # Analyze each bucket
        buckets_info = []
        for bucket in buckets:
            bucket_name = bucket['Name']
            try:
                bucket_info = analyze_s3_bucket(s3_client, bucket_name)
                buckets_info.append(bucket_info)
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Cannot analyze bucket {bucket_name}: {e}{Style.RESET_ALL}")
        
        # Sort buckets by security score (lowest to highest)
        buckets_info.sort(key=lambda x: x['security_score'])
        
        # Generate summary
        print("\n")
        print(f"{Fore.CYAN}========================================================{Style.RESET_ALL}")
        print(f"{Fore.CYAN}                  SECURITY SUMMARY                      {Style.RESET_ALL}")
        print(f"{Fore.CYAN}========================================================{Style.RESET_ALL}")
        print(generate_summary_table(buckets_info))
        print("")
        
        # Show detailed information for buckets with score below 60
        critical_buckets = [b for b in buckets_info if b['security_score'] < 60]
        if critical_buckets:
            print(f"{Fore.RED}========================================================{Style.RESET_ALL}")
            print(f"{Fore.RED}   BUCKETS REQUIRING IMMEDIATE ATTENTION ({len(critical_buckets)}){Style.RESET_ALL}")
            print(f"{Fore.RED}========================================================{Style.RESET_ALL}")
            
            for bucket in critical_buckets:
                print(generate_detailed_report(bucket))
                print("")
        
        # Generate statistics
        total_score = sum(b['security_score'] for b in buckets_info)
        avg_score = total_score / len(buckets_info) if buckets_info else 0
        
        secure_count = len([b for b in buckets_info if b['security_score'] >= 75])
        moderate_count = len([b for b in buckets_info if 60 <= b['security_score'] < 75])
        critical_count = len([b for b in buckets_info if b['security_score'] < 60])
        
        print(f"{Fore.CYAN}========================================================{Style.RESET_ALL}")
        print(f"{Fore.CYAN}                  OVERALL STATISTICS                    {Style.RESET_ALL}")
        print(f"{Fore.CYAN}========================================================{Style.RESET_ALL}")
        print(f"Total number of buckets: {len(buckets_info)}")
        print(f"Average security score: {Fore.CYAN}{round(avg_score, 1)}/100{Style.RESET_ALL}")
        print(f"Secure buckets (75-100): {Fore.GREEN}{secure_count}{Style.RESET_ALL} ({round(secure_count/len(buckets_info)*100 if buckets_info else 0, 1)}%)")
        print(f"Moderately secure buckets (60-74): {Fore.YELLOW}{moderate_count}{Style.RESET_ALL} ({round(moderate_count/len(buckets_info)*100 if buckets_info else 0, 1)}%)")
        print(f"Critical buckets (<60): {Fore.RED}{critical_count}{Style.RESET_ALL} ({round(critical_count/len(buckets_info)*100 if buckets_info else 0, 1)}%)")
        
        # Summarize most common issues
        print("\n")
        print(f"{Fore.CYAN}========================================================{Style.RESET_ALL}")
        print(f"{Fore.CYAN}                MOST COMMON SECURITY ISSUES             {Style.RESET_ALL}")
        print(f"{Fore.CYAN}========================================================{Style.RESET_ALL}")
        
        no_encryption = len([b for b in buckets_info if b['encryption']['is_encrypted'] is not True])
        no_versioning = len([b for b in buckets_info if b['versioning']['versioning_enabled'] is not True])
        no_logging = len([b for b in buckets_info if b['logging']['logging_enabled'] is not True])
        public_access = len([b for b in buckets_info if b['public_access']['is_public'] is True])
        no_lifecycle = len([b for b in buckets_info if b['lifecycle']['has_lifecycle'] is not True])
        
        problems = [
            ("No encryption", no_encryption),
            ("No versioning", no_versioning),
            ("No logging", no_logging),
            ("Public access", public_access),
            ("No lifecycle policy", no_lifecycle)
        ]
        
        # Sort issues from most common
        problems.sort(key=lambda x: x[1], reverse=True)
        
        for problem, count in problems:
            percentage = round(count/len(buckets_info)*100 if buckets_info else 0, 1)
            color = Fore.RED if percentage > 50 else (Fore.YELLOW if percentage > 25 else Fore.GREEN)
            print(f"{problem}: {color}{count}/{len(buckets_info)} ({percentage}%){Style.RESET_ALL}")
        
        # Save results to text file
        try:
            report_filename = f"s3_security_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(report_filename, 'w') as f:
                f.write("AWS S3 BUCKETS SECURITY AUDIT\n")
                f.write("=" * 50 + "\n")
                f.write(f"Report generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"AWS Account ID: {get_aws_account_id()}\n")
                f.write("=" * 50 + "\n\n")
                
                f.write("SECURITY SUMMARY\n")
                f.write("=" * 50 + "\n")
                # Save table without colors
                table_data = []
                table_headers = ["Bucket", "Score", "Level", "Public", "Encryption", "Versioning", "Logging", "Policy", "Lifecycle"]
                
                for bucket in buckets_info:
                    table_data.append([
                        bucket['name'],
                        f"{bucket['security_score']}/100",
                        "Very Good" if bucket['security_score'] >= 90 else
                        "Good" if bucket['security_score'] >= 75 else
                        "Moderate" if bucket['security_score'] >= 60 else
                        "Poor" if bucket['security_score'] >= 40 else
                        "Critical",
                        "Yes" if bucket['public_access']['is_public'] is True else "No",
                        "Yes" if bucket['encryption']['is_encrypted'] is True else "No",
                        "Yes" if bucket['versioning']['versioning_enabled'] is True else "No",
                        "Yes" if bucket['logging']['logging_enabled'] is True else "No",
                        "Yes" if bucket['policy']['has_policy'] is True else "No",
                        "Yes" if bucket['lifecycle']['has_lifecycle'] is True else "No"
                    ])
                
                f.write(tabulate(table_data, headers=table_headers, tablefmt="grid") + "\n\n")
                
                f.write("OVERALL STATISTICS\n")
                f.write("=" * 50 + "\n")
                f.write(f"Total number of buckets: {len(buckets_info)}\n")
                f.write(f"Average security score: {round(avg_score, 1)}/100\n")
                f.write(f"Secure buckets (75-100): {secure_count} ({round(secure_count/len(buckets_info)*100 if buckets_info else 0, 1)}%)\n")
                f.write(f"Moderately secure buckets (60-74): {moderate_count} ({round(moderate_count/len(buckets_info)*100 if buckets_info else 0, 1)}%)\n")
                f.write(f"Critical buckets (<60): {critical_count} ({round(critical_count/len(buckets_info)*100 if buckets_info else 0, 1)}%)\n\n")
                
                f.write("MOST COMMON SECURITY ISSUES\n")
                f.write("=" * 50 + "\n")
                for problem, count in problems:
                    percentage = round(count/len(buckets_info)*100 if buckets_info else 0, 1)
                    f.write(f"{problem}: {count}/{len(buckets_info)} ({percentage}%)\n")
                
                f.write("\n\nDETAILED REPORTS FOR CRITICAL BUCKETS\n")
                f.write("=" * 50 + "\n\n")
                
                for bucket in critical_buckets:
                    f.write("=" * 50 + "\n")
                    f.write(f"BUCKET: {bucket['name']}\n")
                    f.write(f"Security score: {bucket['security_score']}/100\n")
                    f.write("=" * 50 + "\n\n")
                    
                    # Write detailed report without colors
                    f.write("1. PUBLIC ACCESS CONTROL\n")
                    f.write(f"Public access: {'Yes' if bucket['public_access']['is_public'] is True else 'No'}\n")
                    f.write(f"BlockPublicAcls: {'Yes' if bucket['public_access']['block_public_acls'] is True else 'No'}\n")
                    f.write(f"BlockPublicPolicy: {'Yes' if bucket['public_access']['block_public_policy'] is True else 'No'}\n")
                    f.write(f"IgnorePublicAcls: {'Yes' if bucket['public_access']['ignore_public_acls'] is True else 'No'}\n")
                    f.write(f"RestrictPublicBuckets: {'Yes' if bucket['public_access']['restrict_public_buckets'] is True else 'No'}\n\n")
                    
                    f.write("2. ENCRYPTION\n")
                    f.write(f"Encryption enabled: {'Yes' if bucket['encryption']['is_encrypted'] is True else 'No'}\n")
                    if bucket['encryption']['is_encrypted'] is True:
                        f.write(f"Encryption type: {bucket['encryption']['encryption_type']}\n")
                        f.write(f"KMS Key ID: {bucket['encryption']['kms_key_id'] if bucket['encryption']['kms_key_id'] else 'N/A'}\n")
                    f.write("\n")
                    
                    f.write("3. VERSIONING\n")
                    f.write(f"Versioning enabled: {'Yes' if bucket['versioning']['versioning_enabled'] is True else 'No'}\n")
                    f.write(f"Versioning status: {bucket['versioning']['status']}\n")
                    f.write(f"MFA Delete: {bucket['versioning']['mfa_delete']}\n\n")
                    
                    f.write("4. LOGGING\n")
                    f.write(f"Logging enabled: {'Yes' if bucket['logging']['logging_enabled'] is True else 'No'}\n")
                    if bucket['logging']['logging_enabled'] is True:
                        f.write(f"Target Bucket: {bucket['logging']['target_bucket']}\n")
                        f.write(f"Target Prefix: {bucket['logging']['target_prefix']}\n")
                    f.write("\n")
                    
                    f.write("5. BUCKET POLICY\n")
                    f.write(f"Policy defined: {'Yes' if bucket['policy']['has_policy'] is True else 'No'}\n")
                    if bucket['policy']['has_policy'] is True:
                        f.write(f"Contains public access: {'Yes' if bucket['policy']['has_public_access'] is True else 'No'}\n")
                        f.write(f"Requires secure transport: {'Yes' if bucket['policy']['has_secure_transport'] is True else 'No'}\n")
                    f.write("\n")
                    
                    f.write("6. LIFECYCLE POLICY\n")
                    f.write(f"Lifecycle policy defined: {'Yes' if bucket['lifecycle']['has_lifecycle'] is True else 'No'}\n")
                    if bucket['lifecycle']['has_lifecycle'] is True:
                        f.write(f"Contains expiration rules: {'Yes' if bucket['lifecycle']['has_expiration'] is True else 'No'}\n")
                        f.write(f"Contains transition rules: {'Yes' if bucket['lifecycle']['has_transition'] is True else 'No'}\n")
                        f.write(f"Number of rules: {bucket['lifecycle']['rules_count']}\n")
                    f.write("\n")
                    
                    f.write("7. CORS CONFIGURATION\n")
                    f.write(f"CORS defined: {'Yes' if bucket['cors']['has_cors'] is True else 'No'}\n")
                    if bucket['cors']['has_cors'] is True:
                        f.write(f"Contains wildcard origin (*): {'Yes' if bucket['cors']['has_wildcard_origin'] is True else 'No'}\n")
                        f.write(f"Number of CORS rules: {bucket['cors']['rules_count']}\n")
                    f.write("\n")
                    
                    f.write("8. OBJECT LOCK\n")
                    f.write(f"Object Lock enabled: {'Yes' if bucket['object_lock']['object_lock_enabled'] is True else 'No'}\n")
                    if bucket['object_lock']['object_lock_enabled'] is True:
                        f.write(f"Retention mode: {bucket['object_lock']['retention_mode']}\n")
                        f.write(f"Retention days: {bucket['object_lock']['retention_days']}\n")
                    f.write("\n")
                    
                    f.write("9. RECOMMENDATIONS\n")
                    # Generate recommendations
                    recommendations = get_recommendations_for_bucket(bucket)
                    
                    if not recommendations:
                        f.write("✅ No recommendations - bucket meets all checked security requirements\n")
                    else:
                        for rec in recommendations:
                            f.write(f"- {rec}\n")
                    
                    f.write("\n" + "=" * 50 + "\n\n")
            
            print(f"\n{Fore.GREEN}Report saved to file: {report_filename}{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Cannot save report to file: {e}{Style.RESET_ALL}")
        
        # Export to JSON
        try:
            json_data = prepare_json_output(buckets_info)
            json_filename = f"s3_security_audit_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            with open(json_filename, 'w') as f:
                json.dump(json_data, f, indent=2, default=str)
            
            print(f"{Fore.GREEN}JSON report saved to: {json_filename}{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Cannot export to JSON: {e}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Unexpected error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()