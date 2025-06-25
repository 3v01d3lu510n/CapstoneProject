import argparse
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'Imports'))

import say  # Import say.py
import findwr  # Import scanwr.py từ thư mục Tools

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

# Thêm tham số -o để gọi say.py
parser.add_argument('-o', '--output', action='store_true', help="Call say.py to print Hello World.")

# Thêm tham số -f để gọi findwr.py 
parser.add_argument('-f', '--find-webroot', action='store_true', help="Call scanwr.py to find webroot.")

# Parse các tham số dòng lệnh
args = parser.parse_args()

if args.output:
    say.print_hello_world()  
if args.find_webroot:
    print(findwr.find_webroot())  
