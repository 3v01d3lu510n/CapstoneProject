import sys
import re
import csv
import subprocess
import os
from typing import List

def is_likely_opcode(token: str) -> bool:
    # Typical PHP opcodes: uppercase, underscores, not too long
    return (
        2 <= len(token) <= 15 and
        re.fullmatch(r'[A-Z_]+', token) is not None and
        not all(c == token[0] for c in token)  # filter out repeated single chars
    )

def extract_opcodes(php_file: str) -> List[str]:

    cmd = [
        "phpdbg",
        "-qrr",    # quiet + run & quit
        "-p*",     # print all opcodes
        php_file
    ]

    proc = subprocess.run(cmd,
                          stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,
                          shell=False)
    stderr_text = proc.stderr.decode('utf-8', errors='replace') if proc.stderr else ""
    if proc.returncode != 0:
        raise RuntimeError(f"phpdbg failed: {proc.stderr.strip()}")

    opcodes: List[str] = []
    for line in stderr_text.splitlines():
        if not line.strip() or not line.lstrip().startswith('L'):
            continue
        columns = line.strip().split()
        if "=" in columns:
            eq_idx = columns.index("=")
            # Opcode is usually right after "="
            if eq_idx + 1 < len(columns) and is_likely_opcode(columns[eq_idx + 1]):
                opcodes.append(columns[eq_idx + 1])
        elif len(columns) >= 3 and is_likely_opcode(columns[2]):
            opcodes.append(columns[2])
    
    return opcodes

def main():
    if len(sys.argv) != 3:
        print("Usage: py opcodes.py <directory> <output_csv>")
        sys.exit(1)
    dir_path = sys.argv[1]
    if not os.path.isdir(dir_path):
        print(f"Error: {dir_path} is not a valid directory.")
        sys.exit(1)
    
    csv_path = sys.argv[2]
    if not csv_path.endswith('.csv'):
        print(f"Error: {csv_path} should be a .csv file.")
        sys.exit(1)
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['filename', 'opcodes']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for root, _, files in os.walk(dir_path):
            for fname in files:
                php_path = os.path.abspath(os.path.join(root, fname))
                if not os.path.isfile(php_path):
                    continue
                try:
                    opcodes = extract_opcodes(php_path)
                    writer.writerow({'filename': php_path, 'opcodes': ','.join(opcodes)})
                except Exception as e:
                    print(f"Error processing {php_path}: {e}")
                    continue

if __name__ == "__main__":
    main()