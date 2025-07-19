import argparse
import sys
import os
import asyncio
sys.path.append(os.path.join(os.path.dirname(__file__), 'Imports'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'Yara'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'TELE_BOT'))
sys.path.append(os.path.join(os.path.dirname(__file__), 'ML_Predict'))
# import say  # Import say.py
# import findwr  # Import scanwr.py từ thư mục Tools



# from Yara import yara_utils

# from TELE_BOT.bot import run_bot

from ML_Predict.predict import scan_and_log as scan_predict_main
def main():
    banner = r"""
=========================================================
  ___ _  _ ___  ___ _        _ _ _  _                  _ 
 | _ \ || | _ \/ __| |_  ___| | | || |___ _  _ _ _  __| |
 |  _/ __ |  _/\__ \ ' \/ -_) | | __ / _ \ || | ' \/ _ |
 |_| |_||_|_|  |___/_||_\___|_|_|_||_\___/\_,_|_||_\__,_|  
                                                 
         Tool is being developed by IAP491_G5 
=========================================================
"""
    print(banner)

    parser = argparse.ArgumentParser(description="PHPShellHound - Scan PHP webshells.")

    # Tùy chọn chức năng
    parser.add_argument('-o', '--output', action='store_true', help="In Hello World từ say.py")
    parser.add_argument('-f', '--find-webroot', action='store_true', help="Tìm webroot bằng scanwr.py")

    parser.add_argument('-s', '--scan', metavar='TARGET', help="Chạy quét webshell bằng ML (predict.py) trên file/thư mục")


    # Thêm tùy chọn của jara
    parser.add_argument("-y", metavar="Yara", help="Folder/file để quét bằng YARA")
    parser.add_argument("-r", metavar="RULE", help="Tập tin rule YARA")
    parser.add_argument("-w", metavar="TARGET", help="File/thư mục để tạo rule SHA1")
    parser.add_argument("-d", metavar="RULE_NAME", help="Tên rule tùy chỉnh")
    parser.add_argument("-g", metavar="OUTPUT", default="file_rules.yar", help="Tên file rule xuất ra")

    # Chạy thêm bot nữa
    parser.add_argument('--bot', action='store_true', help="Chạy Telegram bot.")

    args = parser.parse_args()

    if args.output:
        say.print_hello_world()

    if args.find_webroot:
        print(findwr.find_webroot())

    if args.bot:
        asyncio.run(run_bot())

    if args.scan:
        scan_predict_main(args.scan)  # truyền đúng đối số


    if args.y and args.r:
        yara_utils.scan_with_yara(args.y, args.r)
    elif args.w:
        hash_utils.handle_hash_generation(
            target=args.w,
            output=args.g,
            rule_name=args.d
        )
    elif not (args.output or args.find_webroot or args.y or args.w or args.scan):
        parser.print_help()

if __name__ == "__main__":
    main()
