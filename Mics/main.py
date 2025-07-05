import argparse
import os
from hash_utils import scan_file, scan_directory
from yara_utils import generate_whitelist_rule, scan_with_yara

def main():
    parser = argparse.ArgumentParser(description="Auto Webshell Detector (SHA1)")
    parser.add_argument("--scan", help="Folder/file to scan with YARA CLI")
    parser.add_argument("--rule", help="YARA rule file for scanning")
    parser.add_argument("target", nargs="?", help="Folder/file to hash and generate rule")
    parser.add_argument("--output", default="file_rules.yar", help="Output YARA rule file")
    args = parser.parse_args()

    if args.scan and args.rule:
        scan_with_yara(args.scan, args.rule)
    elif args.target:
        if os.path.isdir(args.target):
            hash_data = scan_directory(args.target)
        elif os.path.isfile(args.target):
            hash_data = scan_file(args.target)
        else:
            print("[!] Target not found.")
            return
        generate_whitelist_rule(hash_data, args.output)
        print(f"[+] Generated whitelist rule: {args.output}")
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 