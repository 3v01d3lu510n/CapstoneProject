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

def compute_tf_idf(unique_ngrams, docs, n):
    vocab = {ngram: idx for idx, ngram in enumerate(unique_ngrams)}
    N = len(docs)
    df = Counter()
    doc_ngrams = []

    # Count n-grams in each doc and DF
    for opcodes in docs:
        ngrams = generate_ngrams(opcodes, n)
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

def main():
    if len(sys.argv) != 3:
        print(f"Usage: py {sys.argv[0]} <unique_ngrams_file> <train_opcodes_file>")
        sys.exit(1)
        
    unique_ngrams_file = sys.argv[1]
    train_opcodes_file = sys.argv[2]

    unique_ngrams = read_unique_ngrams(unique_ngrams_file)
    n = len(unique_ngrams[0]) if unique_ngrams else 1
    filenames, docs = read_opcodes(train_opcodes_file)
    tfidf_matrix = compute_tf_idf(unique_ngrams, filenames, docs, n)

    # Write output
    with open("data_tfidf_2_matrix.csv", "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        header = ["filename", "tf-idf output"]
        writer.writerow(header)
        for fname, row in zip(filenames, tfidf_matrix):
            tfidf_str = ",".join(str(x) for x in row)
            writer.writerow([fname, tfidf_str])

    print("TF-IDF matrix written to tfidf_matrix.csv")

if __name__ == "__main__":
    main()