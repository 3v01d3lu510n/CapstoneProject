import argparse
import sys
import os
import asyncio

sys.path.append(os.path.join(os.path.dirname(__file__), 'Imports'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'Yara'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'TELE_BOT'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'ML_Predict'))

from Imports.findwr import find_webroot
from Yara import yara_utils
from Imports.hash_utils import handle_hash_generation, print_hashes
from TELE_BOT.bot import run_bot
from ML_Predict.predict import ml_scan_and_log as scan_predict_main, yara_scan_and_log as auto_scan


def main():
    banner = r"""
=========================================================
  ___ _  _ ___  ___ _        _ _ _  _                  _ 
 | _ \ || | _ \/ __| |_  ___| | | || |___ _  _ _ _  __| |
 |  _/ __ |  _/\__ \ ' \/ -_) | | __ / _ \ || | ' \/ _  |
 |_| |_||_|_|  |___/_||_\___|_|_|_||_\___/\_,_|_||_\__,_|  

         Tool is being developed by IAP491_G5 
=========================================================
"""
    print(banner)

    parser = argparse.ArgumentParser(description="PHPShellHound - Scan PHP webshells.")

    # ML-based detection
    parser.add_argument("-s",'--scan', metavar='TARGET', help="Chạy quét webshell bằng ML (predict.py) trên file/thư mục")

    # Auto scan
    parser.add_argument("-a", "--auto", metavar="PATH", nargs="?", const="", help="Tự động quét bằng Yara và ML. Dùng kèm -r hoặc --root để quét webroot.")
    
    # Find Web root
    parser.add_argument("-r", "--root", action='store_true', help="Tìm web root và dùng với -a để quét webroot.")
<<<<<<< Updated upstream

=======
>>>>>>> Stashed changes

    # YARA scan
    parser.add_argument("-y", metavar="Yara", help="Folder/file để quét bằng YARA CLI (Không ghi log)")
    # SHA1-based rule generation
    parser.add_argument("-w", metavar="TARGET", help="Folder/file tạo rule hash")
    parser.add_argument("-o", action="store_true", help="Output YARA rule file (không nhập sẽ tạo file với date)")

    # Telegram bot
    parser.add_argument('--bot', action='store_true', help="Chạy Telegram bot.")

    args = parser.parse_args()

    # 1. ML-based scan
    if args.scan:
        scan_predict_main(args.scan)
        
    # 2. Auto scan
    elif args.auto is not None:
        target_path = args.auto

        if args.root:
            target_path = find_webroot()
            if target_path:
                print(f"[+] Webroot được phát hiện: {target_path}")
            else:
                print("[!] Không tìm thấy webroot.")
                return

        if target_path and os.path.isdir(target_path):
            print(f"[*] Quét thư mục: {target_path}")
            yara_utils.scan_with_all_rules(target_path, write_log=True, show_output=False)
            auto_scan()
        else:
            print(f"[!] Không thể quét. Thư mục không hợp lệ: {target_path}")

    elif args.root:
        print(find_webroot())
    
    # 3. YARA scan
    elif args.y:
        yara_utils.scan_with_all_rules(args.y, write_log=False, show_output=True)
        
    elif args.w:
        if args.o:
            handle_hash_generation(args.w)
        else:
            print_hashes(args.w)
            
    # 4. Telegram bot
    elif args.bot:
        asyncio.run(run_bot())

    # 5. Help
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
