import os
import hashlib
import argparse
from collections import defaultdict

def calculate_hash(file_path, hash_algorithm="md5", block_size=65536):
    """Compute the hash of a file using the specified algorithm"""
    hasher = hashlib.new(hash_algorithm)
    try:
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(block_size)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {str(e)}")
        return None

def find_duplicate_files(directory, hash_algo="md5", recursive=False, min_size=1):
    """Find duplicate files in a directory"""
    hashes = defaultdict(list)
    total_files = 0
    total_size = 0

    for root, dirs, files in os.walk(directory):
        for filename in files:
            file_path = os.path.join(root, filename)
            
            # Skip symbolic links
            if os.path.islink(file_path):
                continue
                
            file_size = os.path.getsize(file_path)
            
            # Skip files smaller than the minimum size
            if file_size < min_size:
                continue
                
            file_hash = calculate_hash(file_path, hash_algo)
            if file_hash:
                hashes[file_hash].append(file_path)
                total_files += 1
                total_size += file_size
        
        # Stop if not in recursive mode
        if not recursive:
            break

    # Filter only hashes with more than one file
    duplicates = {h: files for h, files in hashes.items() if len(files) > 1}
    
    return duplicates, total_files, total_size

def main():
    parser = argparse.ArgumentParser(description='Find and process duplicate files using hash values')
    parser.add_argument('directory', nargs='?', default='.', help='Directory to scan (default: current directory)')
    parser.add_argument('-a', '--algorithm', choices=['md5', 'sha1', 'sha256'], default='md5', help='Hash algorithm (default: md5)')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively scan subdirectories')
    parser.add_argument('-s', '--min-size', type=int, default=1, help='Minimum file size (bytes) to process (default: 1)')
    parser.add_argument('-d', '--delete', action='store_true', help='Delete duplicate files (keep the first one)')
    parser.add_argument('-l', '--list-only', action='store_true', help='Only list duplicates, do not delete')
    parser.add_argument('-o', '--output', help='Export results to a CSV file')

    args = parser.parse_args()

    print(f" Scanning directory: {os.path.abspath(args.directory)}")
    print(f" Hash algorithm: {args.algorithm.upper()}")
    print(f" Recursive scan: {'Yes' if args.recursive else 'No'}")
    print(f" Minimum file size: {args.min_size} bytes\n")

    duplicates, total_files, total_size = find_duplicate_files(
        directory=args.directory,
        hash_algo=args.algorithm,
        recursive=args.recursive,
        min_size=args.min_size
    )

    # Statistics
    duplicate_count = sum(len(files) - 1 for files in duplicates.values())
    duplicate_groups = len(duplicates)
    wasted_space = sum(os.path.getsize(files[0]) * (len(files) - 1) for files in duplicates.values())

    print("\n" + "=" * 50)
    print(f" ANALYSIS RESULT:")
    print(f" Total files scanned: {total_files} files")
    print(f" Total size: {total_size / (1024*1024):.2f} MB")
    print(f" Duplicate groups: {duplicate_groups}")
    print(f" Total duplicate files: {duplicate_count} files")
    print(f" Wasted disk space: {wasted_space / (1024*1024):.2f} MB")
    print("=" * 50 + "\n")

    # Export to CSV if specified
    if args.output:
        import csv
        with open(args.output, 'w', newline='', encoding='utf-8') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(['Hash', 'File Path', 'Size (bytes)', 'Keep'])
            for file_hash, files in duplicates.items():
                for i, file_path in enumerate(files):
                    size = os.path.getsize(file_path)
                    keep = "Yes" if i == 0 else "No"
                    csv_writer.writerow([file_hash, file_path, size, keep])
        print(f" Results exported to: {args.output}")

    # Handle duplicate file deletion
    deleted_count = 0
    if duplicates:
        for file_hash, files in duplicates.items():
            print(f"\n Hash: {file_hash}")
            print(f" Original file (kept): {files[0]}")
            
            for duplicate in files[1:]:
                action = "TO BE DELETED" if args.delete and not args.list_only else "DUPLICATE"
                print(f"  - [{action}] {duplicate}")
                
                if args.delete and not args.list_only:
                    try:
                        os.remove(duplicate)
                        deleted_count += 1
                    except Exception as e:
                        print(f"    ! Error deleting file: {str(e)}")
    
    # Summary of actions
    if args.delete and not args.list_only:
        print("\n" + "=" * 50)
        print(f" DUPLICATE FILES DELETED")
        print(f" Total files deleted: {deleted_count}")
        print(f" Reclaimed disk space: {wasted_space / (1024*1024):.2f} MB")
        print("=" * 50)
    elif duplicate_count > 0:
        print("\n Re-run with --delete to remove the duplicate files")

if __name__ == "__main__":
    main()
