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
![download-_1_](https://github.com/user-attachments/assets/035fa80b-2d29-4e08-a4dc-088d86256179)

# Features
- **Automated Webroot Discovery**: Quickly scans common web-server paths and mounted drives to locate every document-root directory, eliminating the need for manual path configuration before each scan.
- **Pre-Screening with YARA**: Applies a curated set of YARA signatures to filter out known benign files and flag obvious webshells early, reducing the workload for deeper analysis stages.
- **Scanning Files by Machine Learning**: Feeds surviving candidates into a trained classifier that evaluates entropy, opcode n-grams, TF-IDF vectors, and other statistical features to detect stealthy or novel webshells.
- **Custom YARA Rule Management**: Lets analysts add, modify, enable, or disable YARA rules on the fly—supporting whitelists, experimental heuristics, and threat-intel–driven updates without touching the core code.
- **Hybrid Detection – Combining YARA and Machine Learning**: Seamlessly unifies high-speed YARA signature scanning with deep machine-learning analysis, boosting detection capabilities while significantly reducing scan time.
- **Real-Time Telegram Alerting**: Pushes instantaneous notificationsto a designated Telegram channel so responders can triage threats without waiting for batch reports.

# Installation 
Just use the following command to download the tool
```
git clone https://github.com/3v01d3lu510n/CapstoneProject.git
```
Or you can download by new release. After downloading the compressed archive, move it to the directory you intend to scan (or any location of your choice) and extract its contents.
- Windows: Launch an elevated Command Prompt (Run as Administrator), temporarily disable Windows Defender because it may misidentify the bundled YARA webshell rule as malware, and then execute phpshellhound.py..
- Linux: Execute the script with root privileges.

# Requirements
For the best performance of the tool, run the script below and fulfill the following version requirements
- Python < 3.12
```
pip3 install -r requirements.txt
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


