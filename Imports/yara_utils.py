from datetime import datetime
import subprocess
import os
from pathlib import Path
import yara
import re

def generate_whitelist_rule(hash_data, rule_file):
    """
    Tạo rule YARA tối ưu hóa sử dụng Bloom Filter approach
    Thay vì so sánh từng hash với !=, sử dụng == với not() wrapper
    """
    sha1_list = list(hash_data.values())
    
    with open(rule_file, 'w', encoding='utf-8') as f:
        f.write('import "hash"\n')
        f.write("// Whitelist SHA1\n")
        f.write(f"// Generated on: {datetime.now()}\n")
        f.write(f"// Total hashes: {len(sha1_list)}\n\n")
        
        f.write("rule whitelist_sha1 {\n")
        f.write("    meta:\n")
        f.write(f"        description = \"Whitelist SHA1 - {len(sha1_list)} hashes\"\n")
        f.write("        author = \"Auto Webshell Detector\"\n")
        f.write(f"        date = \"{datetime.now().strftime('%Y-%m-%d')}\"\n")
        f.write(f"        total_hashes = {len(sha1_list)}\n")
        
        f.write("    condition:\n")
        f.write("        not (\n")
        
        # Sử dụng Bloom Filter approach: == thay vì !=
        hash_conditions = []
        for sha1 in sha1_list:
            hash_conditions.append(f'            hash.sha1(0, filesize) == "{sha1}"')
        
        f.write(" or\n".join(hash_conditions))
        f.write("\n        )\n}\n")

def append_hashes_to_rule(hash_data, rule_file, rule_name="whitelist_sha1"):
    """
    Thêm hash mới vào trong rule hiện tại thay vì tạo rule mới
    """
    sha1_list = list(hash_data.values())
    
    if not os.path.exists(rule_file):
        print(f"❌ Rule file not found: {rule_file}")
        return False
    
    # Đọc file hiện tại
    with open(rule_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Tìm rule cần append
    rule_pattern = rf'rule\s+{rule_name}\s*{{(.*?)}}'
    rule_match = re.search(rule_pattern, content, re.DOTALL)
    
    if not rule_match:
        print(f"❌ Rule '{rule_name}' not found in {rule_file}")
        return False
    
    rule_content = rule_match.group(1)
    
    # Tìm vị trí cuối của condition để thêm hash mới
    condition_pattern = r'condition:\s*\n\s*not\s*\(\s*\n(.*?)\s*\)\s*\n'
    condition_match = re.search(condition_pattern, rule_content, re.DOTALL)
    
    if not condition_match:
        print(f"❌ Condition not found in rule '{rule_name}'")
        return False
    
    existing_conditions = condition_match.group(1)
    
    # Tạo hash conditions mới với 'or' ở đầu mỗi dòng (trừ dòng đầu tiên)
    new_hash_conditions = []
    for i, sha1 in enumerate(sha1_list):
        if i == 0:
            new_hash_conditions.append(f'            hash.sha1(0, filesize) == "{sha1}"')
        else:
            new_hash_conditions.append(f'            hash.sha1(0, filesize) == "{sha1}"')
    
    # Thêm hash mới vào cuối (trước dòng cuối cùng)
    lines = existing_conditions.split('\n')
    
    # Tìm dòng cuối cùng (thường là dòng trống hoặc dòng cuối của hash cuối)
    last_hash_line = -1
    for i, line in enumerate(lines):
        if 'hash.sha1(0, filesize) == "' in line:
            last_hash_line = i
    
    if last_hash_line == -1:
        print("❌ No existing hash conditions found")
        return False
    
    # Chèn hash mới sau hash cuối cùng
    new_lines = lines[:last_hash_line + 1]
    
    # Thêm 'or' vào cuối dòng hash cuối cùng nếu chưa có
    if not new_lines[last_hash_line].strip().endswith('or'):
        new_lines[last_hash_line] = new_lines[last_hash_line].rstrip() + ' or'
    
    # Thêm các hash mới với 'or' ở đầu (trừ hash đầu tiên)
    for i, hash_condition in enumerate(new_hash_conditions):
        if i == 0:
            # Hash đầu tiên không cần 'or' ở đầu vì đã có 'or' ở cuối dòng trước
            new_lines.append(hash_condition)
        else:
            # Các hash tiếp theo cần 'or' ở cuối dòng trước
            new_lines[-1] = new_lines[-1].rstrip() + ' or'
            new_lines.append(hash_condition)
    
    new_lines.extend(lines[last_hash_line + 1:])
    
    # Cập nhật condition
    new_condition = '\n'.join(new_lines)
    new_rule_content = re.sub(condition_pattern, f'condition:\n        not (\n{new_condition}\n        )\n', rule_content, flags=re.DOTALL)
    
    # Cập nhật metadata
    total_hashes_match = re.search(r'total_hashes\s*=\s*(\d+)', new_rule_content)
    if total_hashes_match:
        current_total = int(total_hashes_match.group(1))
        new_total = current_total + len(sha1_list)
        new_rule_content = re.sub(r'total_hashes\s*=\s*\d+', f'total_hashes = {new_total}', new_rule_content)
    
    # Cập nhật description
    desc_match = re.search(r'description\s*=\s*"([^"]*)"', new_rule_content)
    if desc_match:
        current_desc = desc_match.group(1)
        new_desc = current_desc.replace(f" - {current_total} hashes", f" - {new_total} hashes")
        new_rule_content = re.sub(r'description\s*=\s*"[^"]*"', f'description = "{new_desc}"', new_rule_content)
    
    # Thay thế rule cũ bằng rule mới
    new_content = re.sub(rule_pattern, f'rule {rule_name} {{{new_rule_content}}}', content, flags=re.DOTALL)
    
    # Ghi lại file
    with open(rule_file, 'w', encoding='utf-8') as f:
        f.write(new_content)
    
    print(f"✅ Added {len(sha1_list)} hashes to rule '{rule_name}' in {rule_file}")
    print(f"   New total hashes: {new_total}")
    return True

def append_whitelist_rule(hash_data, rule_file, rule_name=None):
    """
    Thêm rule YARA mới vào cuối file thay vì ghi đè
    """
    sha1_list = list(hash_data.values())
    
    # Tạo tên rule mới nếu không được chỉ định
    if rule_name is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        rule_name = f"whitelist_sha1_{timestamp}"
    
    # Kiểm tra xem file có tồn tại không
    file_exists = os.path.exists(rule_file)
    
    with open(rule_file, 'a', encoding='utf-8') as f:
        # Thêm import nếu file mới
        if not file_exists:
            f.write('import "hash"\n')
            f.write("// Whitelist SHA1 Rules (Appended)\n")
            f.write(f"// First rule generated on: {datetime.now()}\n\n")
        
        # Thêm comment cho rule mới
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
        
        # Sử dụng Bloom Filter approach: == thay vì !=
        hash_conditions = []
        for sha1 in sha1_list:
            hash_conditions.append(f'            hash.sha1(0, filesize) == "{sha1}"')
        
        f.write(" or\n".join(hash_conditions))
        f.write("\n        )\n}\n\n")
    
    print(f"✅ Appended rule '{rule_name}' with {len(sha1_list)} hashes to {rule_file}")

def scan_with_yara(target_path, yara_rule_file):
    """Scan file hoặc thư mục với YARA rule, hỗ trợ tên file Unicode"""
    print("=== YARA SCAN MODE ===")
    print(f"Target: {target_path}")
    print(f"YARA rule: {yara_rule_file}")
    try:
        rules = yara.compile(filepath=yara_rule_file)
    except yara.Error as e:
        print(f"❌ Error loading YARA rule: {e}")
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
            print(f"   ⚠️ Skipping file {path}: không thể mở ({e})")
            return
        try:
            matches = rules.match(data=data)
        except Exception as e:
            print(f"   ⚠️ Lỗi scan {path}: {e}")
            return
        if matches:
            print(f"\n🚨 DETECTED: {path}")
            for m in matches:
                print(f"   Rule: {m.rule}")
                for k, v in m.meta.items():
                    print(f"      {k}: {v}")
            detected.append(path)

    if os.path.isfile(target_path):
        scan_file(target_path)
    else:
        for fp in Path(target_path).rglob("*"):
            if fp.is_file():
                scan_file(str(fp))

    print(f"\n=== YARA SCAN SUMMARY ===")
    print(f"Total files scanned: {total}")
    print(f"Webshells detected: {len(detected)}")
    if detected:
        print("\nList:")
        for f in detected:
            print(f"   - {f}")
    else:
        print("✅ No webshells detected!") 