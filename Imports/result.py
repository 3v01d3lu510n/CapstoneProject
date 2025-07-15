import os
import json
import datetime
import hashlib

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

def create_log_file(total_files_found, webshell_files, unable_files, log_dir="logs", filename=None):
    # Create a detailed log file JSON for a list of file paths (results after scan).
    # Create a folder 'logs' if it doesn't exist and save the file 'log+timescan.json'
    ensure_directory(log_dir)
    if filename is None:
        logs_path = os.path.join(log_dir, "log.json")
    else:
        logs_path = os.path.join(log_dir, filename)

    webshell_data = {
        "path": [],
        "CreationDate": [],
        "Hash_MD5": [],
        "Hash_SHA-1": [],
        "Extension": []
    }
    
    for path in webshell_files:
        try:
            creation_timestamp = os.path.getctime(path)
            creation_date = datetime.datetime.fromtimestamp(creation_timestamp).strftime('%d/%m/%Y')
            md5, sha1 = get_file_hashes(path)
            _, extension = os.path.splitext(path)

            webshell_data["path"].append(path)
            webshell_data["CreationDate"].append(creation_date)
            webshell_data["Hash_MD5"].append(md5)
            webshell_data["Hash_SHA-1"].append(sha1)
            webshell_data["Extension"].append(extension)
        except Exception as e:
            print(f"Could not process file {path}: {e}")

    log_content = {
        "TotalFilesFound": total_files_found,
        "PotentialWebshells": len(webshell_files),
        "TotalFilesIgnored": len(unable_files),
        "WebshellPaths": webshell_data,
        "FilesIgnoredPath": unable_files,
        "ScanTime": datetime.datetime.now().strftime("%d/%m/%Y-%H:%M:%S")
    }

    with open(logs_path, 'w', encoding='utf-8') as f:
        json.dump(log_content, f, indent=4, ensure_ascii=False)
    print(f"Detailed log file saved at: {logs_path}")

def create_summary_file(total_files_found, webshell_files, unable_files, summary_dir="summary", filename=None):
    # Create a summary file JSON from a list of file paths (result after scan).
    # Create a folder 'summary' if it doesn't exist and save the file 'summary+timescan.json'
    ensure_directory(summary_dir)
    if filename is None:
        summary_path = os.path.join(summary_dir, "summary.json")
    else:
        summary_path = os.path.join(summary_dir, filename)
    
    summary_content = {
        "TotalFilesFound": total_files_found,
        "PotentialWebshells": len(webshell_files),
        "TotalFilesIgnored": len(unable_files),
        "WebshellPaths": {
            "name": [os.path.basename(p) for p in webshell_files]
        },
        "FilesIgnoredPath": unable_files,
        "ScanTime": datetime.datetime.now().strftime("%d/%m/%Y-%H:%M:%S")
    }

    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(summary_content, f, indent=4, ensure_ascii=False)
    print(f"Summary file scanned webshell saved at: {summary_path}")