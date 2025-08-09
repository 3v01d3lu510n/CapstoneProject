import os
import json
import datetime
import hashlib
import csv

def ensure_directory(directory_name):
    # Checks if a folder in the directory exists, and if not, creates it.
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)

def get_file_hashes(file_path):
    # Calculates the MD5 and SHA-1 hashes of a file.
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    try:
        with open(file_path, "rb") as f:
            # Read and update hash string value in blocks of 4096 bytes to avoid memory issues with large files
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
        return md5_hash.hexdigest(), sha1_hash.hexdigest()
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None, None
    except Exception as e:
        print(f"An error occurred while hashing {file_path}: {e}")
        return None, None

def create_log_file(total_files_found, webshell_files, not_webshell_files, unable_files, log_dir="logs"):
    # Create a detailed log file JSON for a list of file paths (results after scan).
    # Create a folder 'logs' if it doesn't exist and save the file 'log+timescan.json'
    ensure_directory(log_dir)
    existing_log = [f for f in os.listdir(log_dir) if "scan_log" in f and ".json" in f]
    count = len(existing_log)
    logs_path = os.path.join(log_dir, f"scan_log_{count+1}.json")
    csv_path = os.path.join(log_dir, f"scan_log_{count+1}.csv")

    webshell_logs_list = []
    for path in webshell_files:
        try:
            creation_timestamp = os.path.getctime(path)
            creation_date = datetime.datetime.fromtimestamp(creation_timestamp).strftime('%d/%m/%Y')
            md5, sha1 = get_file_hashes(path)
            _, extension = os.path.splitext(path)

            webshell_data = {
                "path": path,
                "CreationDate": creation_date,
                "Hash_MD5": md5,
                "Hash_SHA-1": sha1,
                "Extension": extension
            }
            webshell_logs_list.append(webshell_data)
        except Exception as e:
            print(f"Could not process file {path}: {e}")

    not_webshell_logs_list = []
    for path in not_webshell_files:
        try:
            creation_timestamp = os.path.getctime(path)
            creation_date = datetime.datetime.fromtimestamp(creation_timestamp).strftime('%d/%m/%Y')
            md5, sha1 = get_file_hashes(path)
            _, extension = os.path.splitext(path)

            not_webshell_data = {
                "path": path,
                "CreationDate": creation_date,
                "Hash_MD5": md5,
                "Hash_SHA-1": sha1,
                "Extension": extension
            }
            not_webshell_logs_list.append(not_webshell_data)
        except Exception as e:
            print(f"Could not process file {path}: {e}")
    # Write CSV log
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ["path", "Prediction", "CreationDate", "Hash_MD5", "Hash_SHA-1", "Extension"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for item in webshell_logs_list:
            item["Prediction"] = "Webshell" 
            writer.writerow(item)
        for item in not_webshell_logs_list:
            item["Prediction"] = "Not Webshell"
            writer.writerow(item)
        for path in unable_files:
            row = {"path": path, "Prediction": "Unable to detect", "CreationDate": "", "Hash_MD5": "", "Hash_SHA-1": "", "Extension": ""}
            writer.writerow(row)

    log_content = {
        "TotalFilesFound": total_files_found,
        "PotentialWebshells": len(webshell_files),
        "NotWebshell": len(not_webshell_files),
        "TotalFilesIgnored": len(unable_files),
        "WebshellPaths": webshell_logs_list,
        "NotWebshellPaths": not_webshell_logs_list,
        "FilesIgnoredPath": unable_files,
        "ScanTime": datetime.datetime.now().strftime("%d/%m/%Y-%H:%M:%S")
    }

    with open(logs_path, 'w', encoding='utf-8') as f:
        json.dump(log_content, f, indent=4, ensure_ascii=False)
    print(f"Detailed log file saved at: {logs_path}")

def create_summary_file(total_files_found, webshell_files, unable_files, summary_dir="logs"):
    # Create a summary file JSON from a list of file paths (result after scan).
    ensure_directory(summary_dir)
    existing_logs = [f for f in os.listdir(summary_dir) if "summary_log" in f and ".json" in f]
    count = len(existing_logs)
    summary_path = os.path.join(summary_dir, f"summary_log_{count + 1}.json")
    csv_path = os.path.join(summary_dir, f"summary_log_{count + 1}.csv")
    scan_time = datetime.datetime.now().strftime("%d/%m/%Y-%H:%M:%S")
    summary_content = {
        "TotalFilesFound": total_files_found,
        "PotentialWebshells": len(webshell_files),
        "TotalFilesIgnored": len(unable_files),
        "WebshellPaths": {
            "name": [os.path.basename(p) for p in webshell_files]
        },
        "FilesIgnoredPath": [
            p for p in unable_files
        ],
        "ScanTime": datetime.datetime.now().strftime("%d/%m/%Y-%H:%M:%S")
    }

    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary_content, f, indent=4, ensure_ascii=False)    
    # Write CSV summary
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ["name", "ScanTime"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for p in webshell_files:
            writer.writerow({"name": os.path.basename(p), "ScanTime": scan_time})
