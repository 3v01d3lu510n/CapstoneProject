import sys
import re
import csv
import subprocess
from collections import Counter
from typing import List
import numpy as np

csv.field_size_limit(2**31 - 1)  # Increase field size limit for large CSVs

class TFIDFCalculator:
    
    idf_dataset = "idf_values.csv"
    
    def __init__(self):
        pass
    
    def is_likely_opcode(self, token: str) -> bool:
        # Typical PHP opcodes: uppercase, underscores, not too long
        return (
            2 <= len(token) <= 15 and
            re.fullmatch(r'[A-Z_]+', token) is not None and
            not all(c == token[0] for c in token)  # filter out repeated single chars
        )
    
    def extract_opcodes(self, php_file: str) -> List[str]:

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
                if eq_idx + 1 < len(columns) and self.is_likely_opcode(columns[eq_idx + 1]):
                    opcodes.append(columns[eq_idx + 1])
            elif len(columns) >= 3 and self.is_likely_opcode(columns[2]):
                opcodes.append(columns[2])
        
        return opcodes

    def load_idf(self, idf_csv_path):
        idf_dict = {}
        ngrams = []
        with open(idf_csv_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ngram = tuple(row['ngram'].split(' '))
                idf_dict[ngram] = float(row['idf'])
                ngrams.append(ngram)
        return ngrams, idf_dict
    
    def compute_tf(self, unique_ngrams, opcodes):
        n = len(unique_ngrams[0])
        ngrams_in_file = [tuple(opcodes[i:i+n]) for i in range(len(opcodes)-n+1)]
        counts = Counter(ngrams_in_file)
        total = sum(counts.values())
        tf_vector = [counts[ngram] / total if total > 0 else 0 for ngram in unique_ngrams]
        return tf_vector
    
    def get_tfidf_result(self, file_path):
        unique_ngrams, idf_dict = self.load_idf(self.idf_dataset)
        opcodes = self.extract_opcodes(file_path)
        tf_vector = self.compute_tf(unique_ngrams, opcodes)
        idf_vector = [idf_dict.get(ngram, 0.0) for ngram in unique_ngrams]
        tfidf_vector = np.multiply(tf_vector, idf_vector).tolist()
        return tfidf_vector
    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    tfidf_calculator = TFIDFCalculator()
    
    tfidf_result = tfidf_calculator.get_tfidf_result(file_path)
    for i in tfidf_result:
        print(f"{i}", end=',')