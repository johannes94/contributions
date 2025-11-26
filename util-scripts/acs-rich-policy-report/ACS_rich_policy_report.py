#!/usr/bin/env python3
"""
Script to generate an enriched report of ACS (Advanced Cluster Security) policies with 
human-readable MITRE ATT&CK information and export them to a CSV file.

This tool fetches the MITRE ATT&CK framework to provide tactics and techniques with 
descriptions, not just IDs.

Usage with API Token:
    export ROX_API_TOKEN="your-api-token"
    export ROX_CENTRAL_ADDRESS="central.example.com:443"
    python3 ACS_rich_policy_report.py [output_file.csv]

Usage with Username/Password:
    export ROX_ADMIN_USER="admin"
    export ROX_ADMIN_PASSWORD="your-password"
    export ROX_CENTRAL_ADDRESS="central.example.com:443"
    python3 ACS_rich_policy_report.py [output_file.csv]

Environment Variables:
    ROX_API_TOKEN: API token for authentication (option 1)
    ROX_ADMIN_USER: Admin username (option 2)
    ROX_ADMIN_PASSWORD: Admin password (option 2)
    ROX_CENTRAL_ADDRESS: ACS Central address (e.g., central.example.com:443)
"""

import requests
import csv
import json
import sys
import os
from typing import List, Dict, Any, Optional
import urllib3

# Disable SSL warnings for demo/development environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ACSRichPolicyReporter:
    def __init__(self, central_address: str, api_token: Optional[str] = None, 
                 username: Optional[str] = None, password: Optional[str] = None):
        """
        Initialize the ACS Rich Policy Reporter
        
        Args:
            central_address: ACS Central address (e.g., central.example.com:443)
            api_token: API token for authentication (optional)
            username: Admin username (optional)
            password: Admin password (optional)
        """
        # Clean up the address to build proper URL
        self.central_address = central_address.strip()
        
        # Remove protocol if present
        if self.central_address.startswith('http://'):
            self.central_address = self.central_address[7:]
        elif self.central_address.startswith('https://'):
            self.central_address = self.central_address[8:]
        
        # Build base URL
        self.base_url = f"https://{self.central_address}"
        
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json'
        })
        
        # Set up authentication
        if api_token:
            self.session.headers.update({
                'Authorization': f'Bearer {api_token}'
            })
            self.auth_method = "API Token"
        elif username and password:
            self.session.auth = (username, password)
            self.auth_method = "Username/Password"
        else:
            raise ValueError("Either api_token or username/password must be provided")
    
    def fetch_mitre_framework(self) -> Dict[str, Dict[str, str]]:
        """
        Fetch MITRE ATT&CK framework from ACS
        
        Returns:
            Dictionary mapping MITRE IDs to names
        """
        url = f"{self.base_url}/v1/mitreattackvectors"
        
        try:
            response = self.session.get(url, verify=False)
            response.raise_for_status()
            data = response.json()
            
            mitre_map = {}
            vectors = data.get('mitreAttackVectors', [])
            
            for vector in vectors:
                tactic = vector.get('tactic', {})
                tactic_id = tactic.get('id', '')
                tactic_name = tactic.get('name', '')
                
                if tactic_id and tactic_name:
                    mitre_map[tactic_id] = tactic_name
                
                # Map techniques
                techniques = vector.get('techniques', [])
                for technique in techniques:
                    tech_id = technique.get('id', '')
                    tech_name = technique.get('name', '')
                    if tech_id and tech_name:
                        mitre_map[tech_id] = tech_name
            
            return mitre_map
        except requests.exceptions.RequestException as e:
            print(f"Warning: Could not fetch MITRE framework: {e}", file=sys.stderr)
            return {}
    
    def fetch_policy_list(self) -> List[str]:
        """
        Fetch list of policy IDs from the ACS API
        
        Returns:
            List of policy IDs
        """
        url = f"{self.base_url}/v1/policies"
        
        print(f"Fetching policy list from: {url}")
        print(f"Using authentication method: {self.auth_method}")
        
        try:
            response = self.session.get(url, verify=False)
            response.raise_for_status()
            data = response.json()
            policies = data.get('policies', [])
            return [p.get('id') for p in policies if p.get('id')]
        except requests.exceptions.RequestException as e:
            print(f"\nError fetching policy list: {e}", file=sys.stderr)
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response status: {e.response.status_code}", file=sys.stderr)
                print(f"Response body: {e.response.text[:500]}", file=sys.stderr)
            sys.exit(1)
    
    def fetch_policy_details(self, policy_id: str) -> Dict[str, Any]:
        """
        Fetch full details for a specific policy
        
        Args:
            policy_id: Policy ID
            
        Returns:
            Full policy dictionary with all details including MITRE ATT&CK data
        """
        url = f"{self.base_url}/v1/policies/{policy_id}"
        
        try:
            response = self.session.get(url, verify=False)
            response.raise_for_status()
            # API returns policy object directly, not wrapped
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Warning: Could not fetch details for policy {policy_id}: {e}", file=sys.stderr)
            return {}
    
    def fetch_policies(self) -> List[Dict[str, Any]]:
        """
        Fetch all policies with full details from the ACS API
        
        Returns:
            List of policy dictionaries with full details
        """
        # First get the list of policy IDs
        policy_ids = self.fetch_policy_list()
        print(f"Found {len(policy_ids)} policies")
        
        # Fetch full details for each policy
        print("Fetching full details for each policy...")
        policies = []
        for i, policy_id in enumerate(policy_ids, 1):
            if i % 10 == 0:
                print(f"  Progress: {i}/{len(policy_ids)}")
            policy = self.fetch_policy_details(policy_id)
            if policy:
                policies.append(policy)
        
        return policies
    
    def format_mitre_tactics(self, mitre_vectors: List[Dict[str, Any]], mitre_map: Dict[str, str]) -> str:
        """
        Format MITRE ATT&CK tactics with human-readable names
        
        Args:
            mitre_vectors: List of MITRE ATT&CK vector dictionaries
            mitre_map: Mapping of MITRE IDs to names
        
        Returns:
            Formatted string with tactics and names
        """
        if not mitre_vectors:
            return ""
        
        tactics = []
        for vector in mitre_vectors:
            tactic_id = vector.get('tactic', '')
            if tactic_id:
                tactic_name = mitre_map.get(tactic_id, '')
                if tactic_name:
                    tactics.append(f"{tactic_id} ({tactic_name})")
                else:
                    tactics.append(tactic_id)
        
        return ", ".join(tactics)
    
    def format_mitre_techniques(self, mitre_vectors: List[Dict[str, Any]], mitre_map: Dict[str, str]) -> str:
        """
        Format MITRE ATT&CK techniques with human-readable names
        
        Args:
            mitre_vectors: List of MITRE ATT&CK vector dictionaries
            mitre_map: Mapping of MITRE IDs to names
        
        Returns:
            Formatted string with techniques and names
        """
        if not mitre_vectors:
            return ""
        
        formatted_parts = []
        for vector in mitre_vectors:
            tactic_id = vector.get('tactic', '')
            techniques = vector.get('techniques', [])
            
            if tactic_id and techniques:
                for technique_id in techniques:
                    technique_name = mitre_map.get(technique_id, '')
                    if technique_name:
                        formatted_parts.append(f"{tactic_id}: {technique_id} ({technique_name})")
                    else:
                        formatted_parts.append(f"{tactic_id}: {technique_id}")
        
        return " | ".join(formatted_parts)
    
    def export_to_csv(self, policies: List[Dict[str, Any]], mitre_map: Dict[str, str], output_file: str = "acs_policies.csv"):
        """
        Export policies to a CSV file
        
        Args:
            policies: List of policy dictionaries
            mitre_map: Mapping of MITRE IDs to names
            output_file: Output CSV filename
        """
        if not policies:
            print("No policies found to export", file=sys.stderr)
            return
        
        # Define CSV columns
        fieldnames = [
            'Policy ID',
            'Policy Name',
            'Description',
            'Severity',
            'Disabled',
            'Categories',
            'MITRE ATT&CK Tactics',
            'MITRE ATT&CK Techniques',
            'Lifecycle Stages',
            'Is Default',
            'Enforcement'
        ]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for policy in policies:
                # Extract MITRE ATT&CK information
                mitre_vectors = policy.get('mitreAttackVectors', [])
                tactics_str = self.format_mitre_tactics(mitre_vectors, mitre_map)
                techniques_str = self.format_mitre_techniques(mitre_vectors, mitre_map)
                
                # Extract other fields
                categories = ", ".join(policy.get('categories', []))
                lifecycle_stages = ", ".join(policy.get('lifecycleStages', []))
                
                # Extract enforcement actions
                enforcement_actions = []
                for action in policy.get('enforcementActions', []):
                    enforcement_actions.append(action)
                enforcement_str = ", ".join(enforcement_actions)
                
                row = {
                    'Policy ID': policy.get('id', ''),
                    'Policy Name': policy.get('name', ''),
                    'Description': policy.get('description', ''),
                    'Severity': policy.get('severity', ''),
                    'Disabled': policy.get('disabled', False),
                    'Categories': categories,
                    'MITRE ATT&CK Tactics': tactics_str,
                    'MITRE ATT&CK Techniques': techniques_str,
                    'Lifecycle Stages': lifecycle_stages,
                    'Is Default': policy.get('isDefault', False),
                    'Enforcement': enforcement_str
                }
                
                writer.writerow(row)
        
        print(f"\nSuccessfully exported {len(policies)} policies to {output_file}")
    
    def run(self, output_file: str = "acs_policies.csv"):
        """
        Main execution method
        
        Args:
            output_file: Output CSV filename
        """
        # Fetch MITRE ATT&CK framework
        print("Fetching MITRE ATT&CK framework...")
        mitre_map = self.fetch_mitre_framework()
        print(f"Loaded {len(mitre_map)} MITRE ATT&CK entries")
        print()
        
        # Fetch policies
        policies = self.fetch_policies()
        print(f"\nSuccessfully fetched {len(policies)} policies with full details")
        
        # Count policies with MITRE ATT&CK data
        policies_with_mitre = sum(1 for p in policies if p.get('mitreAttackVectors'))
        print(f"Policies with MITRE ATT&CK data: {policies_with_mitre}")
        
        print(f"\nExporting to {output_file}...")
        self.export_to_csv(policies, mitre_map, output_file)


def main():
    """
    Main entry point
    """
    # Read from standard ACS environment variables
    api_token = os.getenv('ROX_API_TOKEN')
    username = os.getenv('ROX_ADMIN_USER')
    password = os.getenv('ROX_ADMIN_PASSWORD')
    central_address = os.getenv('ROX_CENTRAL_ADDRESS')
    
    # Validation
    if not central_address:
        print("ERROR: ROX_CENTRAL_ADDRESS environment variable is not set", file=sys.stderr)
        print("\nUsage:", file=sys.stderr)
        print("  Option 1 - With API Token:", file=sys.stderr)
        print("    export ROX_API_TOKEN='your-api-token'", file=sys.stderr)
        print("    export ROX_CENTRAL_ADDRESS='central.example.com:443'", file=sys.stderr)
        print("    python3 ACS_rich_policy_report.py [output_file.csv]", file=sys.stderr)
        print("\n  Option 2 - With Username/Password:", file=sys.stderr)
        print("    export ROX_ADMIN_USER='admin'", file=sys.stderr)
        print("    export ROX_ADMIN_PASSWORD='your-password'", file=sys.stderr)
        print("    export ROX_CENTRAL_ADDRESS='central.example.com:443'", file=sys.stderr)
        print("    python3 ACS_rich_policy_report.py [output_file.csv]", file=sys.stderr)
        sys.exit(1)
    
    if not api_token and not (username and password):
        print("ERROR: Either ROX_API_TOKEN or both ROX_ADMIN_USER and ROX_ADMIN_PASSWORD must be set", file=sys.stderr)
        print("\nUsage:", file=sys.stderr)
        print("  Option 1 - With API Token:", file=sys.stderr)
        print("    export ROX_API_TOKEN='your-api-token'", file=sys.stderr)
        print("    export ROX_CENTRAL_ADDRESS='central.example.com:443'", file=sys.stderr)
        print("    python3 ACS_rich_policy_report.py [output_file.csv]", file=sys.stderr)
        print("\n  Option 2 - With Username/Password:", file=sys.stderr)
        print("    export ROX_ADMIN_USER='admin'", file=sys.stderr)
        print("    export ROX_ADMIN_PASSWORD='your-password'", file=sys.stderr)
        print("    export ROX_CENTRAL_ADDRESS='central.example.com:443'", file=sys.stderr)
        print("    python3 ACS_rich_policy_report.py [output_file.csv]", file=sys.stderr)
        sys.exit(1)
    
    # Get output file from command line argument or use default
    if len(sys.argv) > 1:
        output_file = sys.argv[1]
    else:
        output_file = "acs_policies.csv"
    
    print("=" * 60)
    print("ACS Rich Policy Report with MITRE ATT&CK Information")
    print("=" * 60)
    print(f"Central Address: {central_address}")
    print(f"Output File: {output_file}")
    print("=" * 60)
    print()
    
    try:
        reporter = ACSRichPolicyReporter(central_address, api_token, username, password)
        reporter.run(output_file)
        print("\nDone!")
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
