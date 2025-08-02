```
=========================================================
  ___ _  _ ___  ___ _        _ _ _  _                  _ 
 | _ \ || | _ \/ __| |_  ___| | | || |___ _  _ _ _  __| |
 |  _/ __ |  _/\__ \ ' \/ -_) | | __ / _ \ || | ' \/ _` |
 |_| |_||_|_|  |___/_||_\___|_|_|_||_\___/\_,_|_||_\__,_|
                                                                             
         Tool is being developed by IAP491_G5 
=========================================================
```
The PHPShellHound tool is designed to scan the PHP webshell on the server during Incident Response or Compromise Assessment. This tool will be a file that the executable tester is then assigned to scan.

# Demo 

# Features
- **Review code**: Analyze files to find malicious code patterns, sinks, common encoding patterns by **Entropy Calculation**.
- **Scan subfolder**: Use to scan all subfolders.

# Requirements
For the best performance of the tool, run the script below and fulfill the following version requirements
- Python >= 3.12

```
pip3 install -r requirements.txt
```
# Installation 
Just use the following command to download the tool
```
git clone https://github.com/3v01d3lu510n/CapstoneProject.git
```

# Usage
```
┌──(kali㉿kali)-[~]
└─$ python3 phpshellhound.py -h
=========================================================
  ___ _  _ ___  ___ _        _ _ _  _                  _ 
 | _ \ || | _ \/ __| |_  ___| | | || |___ _  _ _ _  __| |
 |  _/ __ |  _/\__ \ ' \/ -_) | | __ / _ \ || | ' \/ _  |
 |_| |_||_|_|  |___/_||_\___|_|_|_||_\___/\_,_|_||_\__,_|

         Tool is being developed by IAP491_G5
=========================================================

options:
  -h, --help            show this help message and exit
  -s TARGET, --scan TARGET
                        Chạy quét webshell bằng ML (predict.py) trên file/thư mục
  -a [PATH], --auto [PATH]
                        Tự động quét bằng Yara và ML. Dùng kèm -r hoặc --root để quét webroot.
  -r, --root            Tìm web root và dùng với -a để quét webroot.
  -y Yara               Folder/file để quét bằng YARA CLI (Không ghi log)
  -w TARGET             Folder/file tạo rule hash
  -o                    Output YARA rule file (không nhập sẽ tạo file với date)
  --bot                 Chạy Telegram bot.
  ```

# Outstanding Issues
## List of Unresolved Issues

## Improvement Proposals

# Project Detail
For more detail, read [these documents](https://github.com/3v01d3lu510n/CapstoneProject/tree/main/Documents) 


