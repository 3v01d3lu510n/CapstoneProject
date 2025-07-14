import csv
import sys
import math
from collections import Counter

csv.field_size_limit(2**31 - 1)

def read_unique_ngrams(filepath):
    with open(filepath, newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        ngrams = [tuple(row) for row in reader]
    return ngrams

def read_opcodes(filepath):
    docs = []
    filenames = []
    with open(filepath, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            filenames.append(row['filename'])
            opcodes = [op.strip() for op in row['opcodes'].split(',') if op.strip()]
            docs.append(opcodes)
    return filenames, docs

def generate_ngrams(opcodes, n):
    return [tuple(opcodes[i:i+n]) for i in range(len(opcodes)-n+1)]

def compute_tf(unique_ngrams, docs, n):
    doc_ngrams = []
    for opcodes in docs:
        ngrams = generate_ngrams(opcodes, n)
        counts = Counter(ngrams)
        doc_ngrams.append(counts)
    tf_matrix = []
    for counts in doc_ngrams:
        total = sum(counts.values())
        row = []
        for ngram in unique_ngrams:
            tf = counts[ngram] / total if total > 0 else 0
            row.append(tf)
        tf_matrix.append(row)
    return tf_matrix

def compute_idf(unique_ngrams, docs, n):
    N = len(docs)
    df = Counter()
    for opcodes in docs:
        ngrams = generate_ngrams(opcodes, n)
        df.update(set(ngrams))
    idf = {}
    for ngram in unique_ngrams:
        idf[ngram] = math.log((N + 1) / (df[ngram] + 1)) + 1  # Smoothing
    return idf

def main():
    if len(sys.argv) != 3:
        print(f"Usage: py {sys.argv[0]} <unique_ngrams_file> <train_opcodes_file>")
        sys.exit(1)
        
    unique_ngrams_file = sys.argv[1]
    train_opcodes_file = sys.argv[2]

    unique_ngrams = read_unique_ngrams(unique_ngrams_file)
    n = len(unique_ngrams[0]) if unique_ngrams else 1
    filenames, docs = read_opcodes(train_opcodes_file)

    # Compute TF and IDF separately
    tf_matrix = compute_tf(unique_ngrams, docs, n)
    idf = compute_idf(unique_ngrams, docs, n)

    # Save IDF values
    with open("idf_values.csv", "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["ngram", "idf"])
        for ngram in unique_ngrams:
            writer.writerow([" ".join(ngram), idf[ngram]])

    # Compute TF-IDF matrix
    tfidf_matrix = []
    for tf_row in tf_matrix:
        row = [tf * idf[ngram] for tf, ngram in zip(tf_row, unique_ngrams)]
        tfidf_matrix.append(row)

    # Write output
    with open("data_tfidf_2_matrix.csv", "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        header = ["filename", "tf-idf output"]
        writer.writerow(header)
        for fname, row in zip(filenames, tfidf_matrix):
            tfidf_str = ",".join(str(x) for x in row)
            writer.writerow([fname, tfidf_str])

    print("TF-IDF matrix written to data_tfidf_2_matrix.csv")
    print("IDF values written to idf_values.csv")

if __name__ == "__main__":
    main()