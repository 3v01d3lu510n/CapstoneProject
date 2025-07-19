from datetime import datetime
import os
from pathlib import Path
import yara
import re

def generate_whitelist_rule(hash_data, rule_file):
    """
    Generate an optimized YARA rule
    """
    sha1_list = list(hash_data.values())
    
    with open(rule_file, 'w', encoding='utf-8') as f:
        f.write('import "hash"\n')
        f.write("// Whitelist SHA1\n")
        f.write(f"// Generated on: {datetime.now()}\n")
        
        f.write("rule whitelist_sha1 {\n")
        f.write("    meta:\n")
        f.write(f"        description = \"Whitelist SHA1 - {len(sha1_list)} hashes\"\n")
        f.write("        author = \"Auto Webshell Detector\"\n")
        f.write(f"        date = \"{datetime.now().strftime('%Y-%m-%d')}\"\n")
        f.write(f"        total_hashes = {len(sha1_list)}\n")
        
        f.write("    condition:\n")
        f.write("        not (\n")
        
        hash_conditions = []
        for sha1 in sha1_list:
            hash_conditions.append(f'            hash.sha1(0, filesize) == "{sha1}"')
        
        f.write(" or\n".join(hash_conditions))
        f.write("\n        )\n}\n")

def append_hashes_to_rule(hash_data, rule_file, rule_name="whitelist_sha1"):
    """
    Append new hashes to the existing rule instead of creating a new rule.
    """
    sha1_list = list(hash_data.values())
    
    # Read the current file
    with open(rule_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find the rule to append
    rule_pattern = rf'rule\s+{rule_name}\s*{{(.*?)}}'
    rule_match = re.search(rule_pattern, content, re.DOTALL)
    
    if not rule_match:
        print(f"Rule '{rule_name}' not found in {rule_file}")
        return False
    
    rule_content = rule_match.group(1)
    
    # Find the end of the condition to add new hashes
    condition_pattern = r'condition:\s*\n\s*not\s*\(\s*\n(.*?)\s*\)\s*\n'
    condition_match = re.search(condition_pattern, rule_content, re.DOTALL)
    
    if not condition_match:
        print(f"Condition not found in rule '{rule_name}'")
        return False
    
    existing_conditions = condition_match.group(1)
    
    # Create new hash conditions
    new_hash_conditions = []
    for sha1 in sha1_list:
        new_hash_conditions.append(f'            hash.sha1(0, filesize) == "{sha1}"')
    
    # Add new hashes after the last hash line
    lines = existing_conditions.split('\n')
    last_hash_line = -1
    for i, line in enumerate(lines):
        if 'hash.sha1(0, filesize) == "' in line:
            last_hash_line = i
    
    if last_hash_line == -1:
        print("No existing hash conditions found")
        return False
    
    new_lines = lines[:last_hash_line + 1]
    if not new_lines[last_hash_line].strip().endswith('or'):
        new_lines[last_hash_line] = new_lines[last_hash_line].rstrip() + ' or'
    for i, hash_condition in enumerate(new_hash_conditions):
        if i == 0:
            new_lines.append(hash_condition)
        else:
            new_lines[-1] = new_lines[-1].rstrip() + ' or'
            new_lines.append(hash_condition)
    new_lines.extend(lines[last_hash_line + 1:])
    new_condition = '\n'.join(new_lines)
    new_rule_content = re.sub(condition_pattern, f'condition:\n        not (\n{new_condition}\n        )\n', rule_content, flags=re.DOTALL)
    total_hashes_match = re.search(r'total_hashes\s*=\s*(\d+)', new_rule_content)
    if total_hashes_match:
        current_total = int(total_hashes_match.group(1))
        new_total = current_total + len(sha1_list)
        new_rule_content = re.sub(r'total_hashes\s*=\s*\d+', f'total_hashes = {new_total}', new_rule_content)
    desc_match = re.search(r'description\s*=\s*"([^"]*)"', new_rule_content)
    if desc_match:
        current_desc = desc_match.group(1)
        new_desc = current_desc.replace(f" - {current_total} hashes", f" - {new_total} hashes")
        new_rule_content = re.sub(r'description\s*=\s*"[^"]*"', f'description = "{new_desc}"', new_rule_content)
    new_content = re.sub(rule_pattern, f'rule {rule_name} {{{new_rule_content}}}', content, flags=re.DOTALL)
    with open(rule_file, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f"Added {len(sha1_list)} hashes to rule '{rule_name}' in {rule_file}")
    print(f"New total hashes: {new_total}")
    return True

def append_whitelist_rule(hash_data, rule_file, rule_name=None):
    """
    Append a new YARA rule to the end of the file instead of overwriting.
    """
    sha1_list = list(hash_data.values())
    if rule_name is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rule_name = f"whitelist_sha1_{timestamp}"
    file_exists = os.path.exists(rule_file)
    with open(rule_file, 'a', encoding='utf-8') as f:
        if not file_exists:
            f.write('import "hash"\n')
            f.write("// Whitelist SHA1 Rules (Appended)\n")
            f.write(f"// First rule generated on: {datetime.now()}\n\n")
        f.write(f"// Rule: {rule_name} - Generated on: {datetime.now()}\n")
        f.write(f"// Total hashes in this rule: {len(sha1_list)}\n\n")
        f.write(f"rule {rule_name} {{\n")
        f.write("    meta:\n")
        f.write(f"        description = \"Whitelist SHA1 - {len(sha1_list)} hashes\"\n")
        f.write("        author = \"Auto Webshell Detector\"\n")
        f.write(f"        date = \"{datetime.now().strftime('%Y-%m-%d')}\"\n")
        f.write(f"        total_hashes = {len(sha1_list)}\n")
        f.write("        appended = true\n")
        f.write("    condition:\n")
        f.write("        not (\n")
        hash_conditions = []
        for sha1 in sha1_list:
            hash_conditions.append(f'            hash.sha1(0, filesize) == "{sha1}"')
        f.write(" or\n".join(hash_conditions))
        f.write("\n        )\n}\n\n")
    print(f"Appended rule '{rule_name}' with {len(sha1_list)} hashes to {rule_file}")

def scan_with_yara(target_path, yara_rule_file):
    """Scan a file or directory with a YARA rule, supports Unicode filenames."""
    print("=== YARA SCAN MODE ===")
    print(f"Target: {target_path}")
    print(f"YARA rule: {yara_rule_file}")
    try:
        rules = yara.compile(filepath=yara_rule_file)
    except yara.Error as e:
        print(f"Error loading YARA rule: {e}")
        return
    detected = []
    total = 0
    def scan_file(path):
        nonlocal detected, total
        total += 1
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception as e:
            print(f"Skipping file {path}: cannot open ({e})")
            return
        try:
            matches = rules.match(data=data)
        except Exception as e:
            print(f"Scan error {path}: {e}")
            return
        if matches:
            detected.append(path)
    if os.path.isfile(target_path):
        scan_file(target_path)
    else:
        for fp in Path(target_path).rglob("*"):
            if fp.is_file():
                scan_file(str(fp))
    if detected:
        print("\nList:")
        for f in detected:
            print(f"   - {f}")
    else:
        print("No webshells detected!")
    
    print(f"\n=== YARA SCAN SUMMARY ===")
    print(f"Total files scanned: {total}")
    print(f"Webshells detected: {len(detected)}") 
