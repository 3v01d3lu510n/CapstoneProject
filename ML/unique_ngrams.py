import csv
import os, sys
from typing import List, Dict, Tuple

csv.field_size_limit(2**31 - 1)  # Increase CSV field size limit

def generate_ngrams(opcodes: list, n: int) -> list:
    return [tuple(opcodes[i:i+n]) for i in range(len(opcodes)-n+1)]

def main():
    if len(sys.argv) != 4:
        print(f"Usage: py {sys.argv[0]} <input_opcodes_file> <output_ngram_file> <n>")
        sys.exit(1)
    
    input_csv = sys.argv[1]
    output_csv = sys.argv[2]
    n = int(sys.argv[3])

    all_ngrams = set()

    with open(input_csv, 'r',newline='', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            opcodes = [op.strip() for op in row['opcodes'].split(',') if op.strip()]
            ngrams = generate_ngrams(opcodes, n)
            all_ngrams.update(ngrams)

    with open(output_csv, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        writer.writerow([f'opcode_{i+1}' for i in range(n)])
        for ngram in sorted(all_ngrams):
            writer.writerow(ngram)

    print(f"Unique {n}-grams written to {output_csv}")

if __name__ == "__main__":
    main()