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
 |  _/ __ |  _/\__ \ ' \/ -_) | | __ / _ \ || | ' \/ _` |
 |_| |_||_|_|  |___/_||_\___|_|_|_||_\___/\_,_|_||_\__,_|
                                                                             
         Tool is being developed by IAP491_G5 
=========================================================

usage: phpshellhound.py [-h HELP] [-p PATH] [-l LOGPATH] [-s SUBDIR] [-e ENTROPY] 

PHPShellHound - Scan PHP webshells.

options:
  -h, --help            show this help message and exit
  -p, --path PATH       Scan Path
  -l, --logpath LOGPATH
                        Log file save path (Do not end with '/')
  -s, --subdirs         Scan subdirectories
  -e, --entropy         Enable entropy scan
```

# Outstanding Issues
## List of Unresolved Issues

## Improvement Proposals

# Project Detail
For more detail, read [these documents](https://github.com/3v01d3lu510n/CapstoneProject/tree/main/Documents) 


