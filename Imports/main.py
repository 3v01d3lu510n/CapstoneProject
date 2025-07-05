import argparse
import os
from hash_utils import scan_file, scan_directory
from yara_utils import generate_whitelist_rule, append_whitelist_rule, append_hashes_to_rule, scan_with_yara

def main():
    parser = argparse.ArgumentParser(description="Auto Webshell Detector (SHA1)")
    parser.add_argument("--scan", help="Folder/file to scan with YARA CLI")
    parser.add_argument("--rule", help="YARA rule file for scanning")
    parser.add_argument("target", nargs="?", help="Folder/file to hash and generate rule")
    parser.add_argument("--output", default="file_rules.yar", help="Output YARA rule file")
    parser.add_argument("--append", action="store_true", help="Append new rule to existing file instead of overwriting")
    parser.add_argument("--append-hashes", action="store_true", help="Add hashes to existing rule instead of creating new rule")
    parser.add_argument("--rule-name", help="Custom name for the rule (when using --append or --append-hashes)")

    args = parser.parse_args()

    if args.scan and args.rule:
        scan_with_yara(args.scan, args.rule)
    elif args.target:
        print("=== HASH GENERATION MODE ===")
        print(f"Target: {args.target}")
        print(f"Output: {args.output}")
        
        if os.path.isfile(args.target):
            hash_data = scan_file(args.target)
        else:
            hash_data = scan_directory(args.target)
        
        if hash_data:
            print(f"\nGenerated {len(hash_data)} hashes")
            
            if args.append_hashes:
                # Thêm hash vào rule hiện tại
                rule_name = args.rule_name or "whitelist_sha1"
                success = append_hashes_to_rule(hash_data, args.output, rule_name)
                if success:
                    print(f"✅ Hashes added to rule '{rule_name}' in {args.output}")
                else:
                    print(f"❌ Failed to add hashes to rule")
            elif args.append:
                # Sử dụng append mode (tạo rule mới)
                append_whitelist_rule(hash_data, args.output, args.rule_name)
                print(f"✅ Rule appended to {args.output}")
            else:
                # Sử dụng overwrite mode (mặc định)
                generate_whitelist_rule(hash_data, args.output)
                print(f"✅ Rule generated: {args.output}")
        else:
            print("❌ No files found to hash")
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 