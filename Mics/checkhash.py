import os
import hashlib

def calculate_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def find_and_delete_duplicate_files(directory):
    hash_map = {}
    deleted_count = 0

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.lower().endswith('.php'):
                file_path = os.path.join(root, file)
                file_hash = calculate_hash(file_path)

                if file_hash in hash_map:
                    os.remove(file_path)
                    deleted_count += 1
                else:
                    hash_map[file_hash] = file_path

php_dir = r"E:\Download\onlyphpwebshell\datasetwebshell"
find_and_delete_duplicate_files(php_dir)