import argparse
import sys
import os
from yara_utils import scan_with_yara
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Imports')))
import hash_utils 
from hash_utils import handle_hash_generation
def main():
    parser = argparse.ArgumentParser(description="Auto Webshell Detector (SHA1)")
    parser.add_argument("-y", metavar="Yara", help="Folder/file to scan with YARA CLI")
    parser.add_argument("-r", metavar="RULE", help="YARA rule file for scanning")
    parser.add_argument("-w", metavar="TARGET", help="Folder/file to hash and generate rule")
    parser.add_argument("-o", metavar="OUTPUT", default="file_rules.yar", help="Output YARA rule file")
    parser.add_argument("-d", metavar="RULE_NAME", help="Custom name for the rule")

    args = parser.parse_args()

    if args.y and args.r:
        scan_with_yara(args.y, args.r)
    elif args.w:
        handle_hash_generation(
            target=args.w,
            output=args.o,
            rule_name=args.d
        )
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 