from datetime import datetime
import subprocess
import os
from pathlib import Path
import yara

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