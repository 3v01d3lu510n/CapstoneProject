import sys
import re
import csv
import subprocess
import math
from collections import Counter
from typing import List

csv.field_size_limit(2**31 - 1)  # Increase field size limit for large CSVs

class TFIDFCalculator:
    
    n_grams_dataset = "dataset_2_grams.csv"
    opcodes_dataset = "dataopcodes_2.csv"
    
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
        """
        Runs phpdbg to dump opcodes for `php_file`, then returns a list of
        opcode names (e.g. ECHO, FETCH_W, etc.), stripping away offsets,
        operands, and any file-path lines.
        """

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
    
    def read_opcodes(self, filepath):
        docs = []
        filenames = []
        with open(filepath, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                filenames.append(row['filename'])
                opcodes = [op.strip() for op in row['opcodes'].split(',') if op.strip()]
                docs.append(opcodes)
        return filenames, docs
    
    def generate_2_grams(self, opcodes):
        return [tuple(opcodes[i:i+2]) for i in range(len(opcodes)-2+1)]
    
    def read_unique_ngrams(self, filepath):
        with open(filepath, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)
            ngrams = [tuple(row) for row in reader]
        return ngrams
    
    def compute_tf_idf(self, unique_ngrams, docs):
        vocab = {ngram: idx for idx, ngram in enumerate(unique_ngrams)}
        N = len(docs)
        df = Counter()
        doc_ngrams = []

        # Count n-grams in each doc and DF
        for opcodes in docs:
            ngrams = self.generate_2_grams(opcodes)
            counts = Counter(ngrams)
            doc_ngrams.append(counts)
            df.update(set(ngrams))

        # Compute IDF
        idf = {}
        for ngram in unique_ngrams:
            idf[ngram] = math.log((N + 1) / (df[ngram] + 1)) + 1  # Smoothing

        # Compute TF-IDF matrix
        tfidf_matrix = []
        for counts in doc_ngrams:
            total = sum(counts.values())
            row = []
            for ngram in unique_ngrams:
                tf = counts[ngram] / total if total > 0 else 0
                row.append(tf * idf[ngram])
            tfidf_matrix.append(row)
        return tfidf_matrix
    
    def get_tfidf_result(self, file_path):
        unique_ngrams = self.read_unique_ngrams(self.n_grams_dataset)
        filenames, docs = self.read_opcodes(self.opcodes_dataset)
        # Extract opcodes from the target file
        target_opcodes = self.extract_opcodes(file_path)
        # Add the target file's opcodes to the docs
        docs.append(target_opcodes)
        # Compute TF-IDF for all docs (including the target file)
        tfidf_matrix = self.compute_tf_idf(unique_ngrams, docs)
        # The last row is the target file
        return tfidf_matrix[-1]
    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    tfidf_calculator = TFIDFCalculator()
    
    tfidf_result = tfidf_calculator.get_tfidf_result(file_path)
    print(f"Extracted opcodes from {file_path}.")
    print(len(tfidf_result))
    print(f"{tfidf_result}")