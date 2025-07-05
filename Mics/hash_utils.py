import os
import hashlib

def calculate_sha1(file_path):
    try:
        with open(file_path, 'rb') as f:
            return hashlib.sha1(f.read()).hexdigest()
    except Exception as e:
        print(f"[!] Error reading {file_path}: {e}")
        return None

def scan_file(file_path):
    sha1 = calculate_sha1(file_path)
    return {file_path: sha1} if sha1 else {}

def scan_directory(dir_path):
    hash_data = {}
    for root, _, files in os.walk(dir_path):
        for name in files:
            file_path = os.path.join(root, name)
            sha1 = calculate_sha1(file_path)
            if sha1:
                hash_data[file_path] = sha1
    return hash_data 