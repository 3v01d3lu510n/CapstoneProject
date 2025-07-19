import os
import sys
import hashlib
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'yara2')))
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

def process_output_argument(output_arg):
    """Xử lý tham số -o và trả về output_file và rule_name"""
    # Giả định thư mục /Yara đã tồn tại, chỉ tạo thư mục /Yara/rule nếu chưa có
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'yara'))
    rule_dir = os.path.join(base_dir, 'rule')
    if not os.path.exists(rule_dir):
        os.makedirs(rule_dir)
        print(f"Created directory: {rule_dir}")
    
    if output_arg == '':
        from datetime import datetime
        date_str = datetime.now().strftime("%d-%m-%Y")
        output_file = os.path.join(rule_dir, f"file_rules_{date_str}.yar")
        rule_name = f"file_rules_{date_str}"
    else:
        if not output_arg.endswith('.yar'):
            output_arg = output_arg + '.yar'
        output_file = os.path.join(rule_dir, output_arg)
        rule_name = output_arg.replace('.yar', '')
    
    return output_file, rule_name

def handle_hash_generation(target, output_file, rule_name):
    """Handle hash and rule generation mode - automatically append if rule already exists"""
    print("=== HASH GENERATION MODE ===")
    print(f"Target: {target}")
    print(f"Output: {output_file}")
    
    if os.path.isfile(target):
        hash_data = scan_file(target)
    else:
        hash_data = scan_directory(target)
    
    if hash_data:
        print(f"Generated {len(hash_data)} hashes")
        
        # Luôn sử dụng rule name là whitelist_sha1
        rule_name = "whitelist_sha1"
        
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
    
