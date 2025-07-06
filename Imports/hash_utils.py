import os
import sys
import hashlib
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Yara')))
import yara_utils
from yara_utils import generate_whitelist_rule, append_whitelist_rule, append_hashes_to_rule
def calculate_sha1(file_path):
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha1(f.read()).hexdigest()
    except Exception as e:
        print(f"[!] Error reading {file_path}: {e}")
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

def handle_hash_generation(target, output, rule_name=None):
    """Handle hash and rule generation mode - automatically append if rule already exists"""
    print("=== HASH GENERATION MODE ===")
    print(f"Target: {target}")
    print(f"Output: {output}")
    
    if os.path.isfile(target):
        hash_data = scan_file(target)
    else:
        hash_data = scan_directory(target)
    
    if hash_data:
        print(f"\nGenerated {len(hash_data)} hashes")
        
        # Automatically decide: append hashes if rule exists, create new if not
        rule_name = rule_name or "whitelist_sha1"
        
        if os.path.exists(output):
            # Check if rule exists in file
            try:
                with open(output, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if f'rule {rule_name}' in content:
                        # Rule exists, append hashes
                        print(f" Rule '{rule_name}' already exists, appending hashes...")
                        success = append_hashes_to_rule(hash_data, output, rule_name)
                        if success:
                            print(f" Hashes added to existing rule '{rule_name}' in {output}")
                        else:
                            print(f" Failed to add hashes to rule")
                    else:
                        # File exists but rule not found, create new rule
                        print(f" File exists but rule '{rule_name}' not found, creating new rule...")
                        append_whitelist_rule(hash_data, output, rule_name)
                        print(f" New rule '{rule_name}' appended to {output}")
            except Exception as e:
                print(f" Error checking existing file: {e}")
                # Create new file if error
                generate_whitelist_rule(hash_data, output)
                print(f" Rule generated: {output}")
        else:
            # File does not exist, create new
            print(f" Creating new rule file: {output}")
            generate_whitelist_rule(hash_data, output)
            print(f" Rule generated: {output}")
    else:
        print(" No files found to hash") 
    
