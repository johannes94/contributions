# ACS Rich Policy Report - Usage Instructions

This script generates an enriched report of policies from Red Hat Advanced Cluster Security (ACS) and exports them to a CSV file with human-readable MITRE ATT&CK information (tactics and techniques with descriptions).

## Authentication Options

### Option 1: Using Username and Password

```bash
export ROX_ADMIN_USER="admin"
export ROX_ADMIN_PASSWORD="your-password"
export ROX_CENTRAL_ADDRESS="central.example.com:443"
python3 ACS_rich_policy_report.py
```

### Option 2: Using API Token

```bash
export ROX_API_TOKEN="your-api-token"
export ROX_CENTRAL_ADDRESS="central.example.com:443"
python3 ACS_rich_policy_report.py
```

## Custom Output File

You can specify a custom output filename:

```bash
python3 ACS_rich_policy_report.py my_policies.csv
```

## Output Format

The CSV will include the following columns:

- **Policy ID** - Unique identifier for the policy
- **Policy Name** - Human-readable policy name
- **Description** - Detailed policy description
- **Severity** - Policy severity level
- **Disabled** - Whether the policy is currently disabled
- **Categories** - Policy categories
- **MITRE ATT&CK Tactics** - Comma-separated list of tactics
- **MITRE ATT&CK Techniques** - Full details with techniques
- **Lifecycle Stages** - When the policy applies (build, deploy, runtime)
- **Is Default** - Whether this is a default ACS policy
- **Enforcement** - Enforcement actions configured

## Example Commands

### Basic usage with username/password

```bash
export ROX_ADMIN_USER="admin"
export ROX_ADMIN_PASSWORD="mypassword123"
export ROX_CENTRAL_ADDRESS="central-acs.example.com:443"
python3 ACS_rich_policy_report.py
```

### Save to specific file

```bash
python3 ACS_rich_policy_report.py production_policies.csv
```

### Using with API token instead

```bash
export ROX_API_TOKEN="eyJhbGciOiJSUzI1NiIsImtpZCI6..."
export ROX_CENTRAL_ADDRESS="central-acs.example.com:443"
python3 ACS_rich_policy_report.py
```

## Notes

- The script uses HTTPS and disables SSL verification for demo environments
- For production use, consider enabling SSL verification
- The script uses standard ACS/StackRox environment variable names

