import os
import sys
import hashlib
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Yara')))
from yara_utils import generate_whitelist_rule, append_whitelist_rule, append_hashes_to_rule
def calculate_sha1(file_path):
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha1(f.read()).hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def scan_file(file_path):
    sha1 = calculate_sha1(file_path)
    return {file_path: sha1} if sha1 else {}

def scan_directory(dir_path):
    hash_data = {}
    for root, _, files in os.walk(dir_path):
        for name in files:
            file_path = os.path.join(root, name)
            sha1 = calculate_sha1(file_path)
            if sha1:
                hash_data[file_path] = sha1
    return hash_data

def print_hashes(target):
    print("=== HASH ONLY MODE ===")
    print(f"Target: {target}")
    if os.path.isfile(target):
        hash_data = scan_file(target)
    else:
        hash_data = scan_directory(target)
    if hash_data:
        print(f"\nGenerated {len(hash_data)} hashes:")
        for file_path, sha1 in hash_data.items():
            print(f"  {file_path}: {sha1}")
    else:
        print("No files found to hash")

def handle_hash_generation(target):
    """Handle hash and rule generation mode - automatically append if rule already exists to rule_yara.yar with rule name whitelist_sha1"""
    print("=== HASH GENERATION MODE ===")
    print(f"Target: {target}")
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Yara'))
    rule_dir = os.path.join(base_dir, 'rule')
    if not os.path.exists(rule_dir):
        os.makedirs(rule_dir)
    output_file = os.path.join(rule_dir, 'rule_yara.yar')
    rule_name = 'whitelist_sha1'
    print(f"Output: {output_file}")
    if os.path.isfile(target):
        hash_data = scan_file(target)
    else:
        hash_data = scan_directory(target)
    if hash_data:
        print(f"Generated {len(hash_data)} hashes")
        if os.path.exists(output_file):
            # Check if rule exists in file
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if f'rule {rule_name}' in content:
                        # Rule exists, append hashes
                        success = append_hashes_to_rule(hash_data, output_file, rule_name)
                        if not success:
                            print(f"Failed to add hashes to rule")
                    else:
                        # File exists but rule not found, create new rule
                        print(f"File exists but rule '{rule_name}' not found, creating new rule...")
                        append_whitelist_rule(hash_data, output_file, rule_name)
                        print(f"New rule '{rule_name}' appended to {output_file}")
            except Exception as e:
                print(f"Error checking existing file: {e}")
                # Create new file if error
                generate_whitelist_rule(hash_data, output_file)
                print(f"Rule generated: {output_file}")
        else:
            # File does not exist, create new
            print(f"Creating new rule file: {output_file}")
            generate_whitelist_rule(hash_data, output_file)
            print(f"Rule generated: {output_file}")
    else:
        print("No files found to hash") 
    
