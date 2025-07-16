import Entropy, DataCharacteristics, tfidf_calculator
import sys, os
from typing import List
import pandas as pd
import joblib
import json
import datetime
import hashlib

class WebshellPredicter:
    
    entropyAnalyzer: Entropy.EntropyAnalyzer
    dataCharacteristics: DataCharacteristics.ASTAnalyzer
    tfidfCalculator: tfidf_calculator.TFIDFCalculator
    model = joblib.load('random_forest_classifier.pkl')
    
    def __init__(self):
        self.entropyAnalyzer = Entropy.EntropyAnalyzer()
        self.dataCharacteristics = DataCharacteristics.ASTAnalyzer()
        self.tfidfCalculator = tfidf_calculator.TFIDFCalculator()
        self.model = joblib.load('random_forest_classifier.pkl')
        pass
    
    def get_entropies(self, file_path: str) -> float:
        return self.entropyAnalyzer.get_file_entropies(file_path)
    
    def get_data_characteristics_flag(self, file_path: str) -> int:
        return self.dataCharacteristics.evaluate_file_characteristics(file_path)
    
    def get_tfidf_result(self, file_path: str) -> List[float]:
        return self.tfidfCalculator.get_tfidf_result(file_path)
        
    def get_file_features(self, file_path: str) -> List[float]:
        entropies = self.get_entropies(file_path)
        characteristics_flag = self.get_data_characteristics_flag(file_path)
        tfidf_result = self.get_tfidf_result(file_path)

        if entropies is None:
            return []
        
        features = [
            entropies['info_entropy'],
            entropies['special_entropy'],
            entropies['quote_entropy'],
            characteristics_flag
        ] + tfidf_result
    
        return features
    
    def predict_file(self, file_path: str):
        features = self.get_file_features(file_path)
        if not features:
            return None

        features_names = ['InfoEntropy', 'SpecialCharEntropy', 'QuoteEntropy', 'characteristics_flag'] + [f'tfidf_{i}' for i in range(len(features) - 4)]
        features_df = pd.DataFrame([features], columns=features_names)
        prediction = self.model.predict(features_df)

        return prediction[0]
    
def get_file_hashes(file_path):
    """Return MD5 and SHA-1 hashes for a file."""
    hash_md5 = hashlib.md5()
    hash_sha1 = hashlib.sha1()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
                hash_sha1.update(chunk)
        return hash_md5.hexdigest(), hash_sha1.hexdigest()
    except Exception as e:
        return "", ""

def get_file_extension(file_path):
    return '.' + os.path.splitext(file_path)[1].lstrip('.').lower()

def get_file_creation_date(file_path):
    """Return the creation date of the file as dd/mm/YYYY."""
    try:
        ctime = os.path.getctime(file_path)
        return datetime.datetime.fromtimestamp(ctime).strftime("%d/%m/%Y")
    except Exception:
        return ""

def scan_directory(dir_path, predicter, webshell_files, not_webshell_files, unable_files, log_lines):
    total_files = 0
    for root, _, files in os.walk(dir_path):
        for file in files:
            abs_path = os.path.abspath(os.path.join(root, file))
            total_files += 1
            try:
                result = predicter.predict_file(abs_path)
                label = 'Webshell' if result == 1 else 'Not a Webshell'
                log_lines.append(f"Prediction for file {abs_path}: {label}")
                file_date = get_file_creation_date(abs_path)
                if label == 'Webshell':
                    md5, sha1 = get_file_hashes(abs_path)
                    ext = get_file_extension(abs_path)
                    webshell_files.append({
                        "path": abs_path,
                        "date": file_date,
                        "Hash_MD5": md5,
                        "Hash_SHA-1": sha1,
                        "Extension": ext
                    })
                else:
                    md5, sha1 = get_file_hashes(abs_path)
                    ext = get_file_extension(abs_path)
                    not_webshell_files.append({
                        "path": abs_path,
                        "date": file_date,
                        "Hash_MD5": md5,
                        "Hash_SHA-1": sha1,
                        "Extension": ext
                    })
            except Exception as e:
                print(f"Unable to detect {abs_path}: {e}")
                unable_files.append({
                    "path": abs_path,
                    "comment": str(e),
                    "date": get_file_creation_date(abs_path)
                })
    return total_files

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file/directory_path>")
        sys.exit(1)

    file_path = sys.argv[1]
    log_lines = []
    predicter = WebshellPredicter()

    webshell_files = []
    not_webshell_files = []
    unable_files = []

    total_files_found = 0

    if os.path.isfile(file_path):
        abs_path = os.path.abspath(file_path)
        total_files_found = 1
        try:
            result = predicter.predict_file(abs_path)
            label = 'Webshell' if result == 1 else 'Not a Webshell'
            log_lines.append(f"Prediction for file {abs_path}: {label}")
            file_date = get_file_creation_date(abs_path)
            if label == 'Webshell':
                md5, sha1 = get_file_hashes(abs_path)
                ext = get_file_extension(abs_path)
                webshell_files.append({
                    "path": abs_path,
                    "date": file_date,
                    "Hash_MD5": md5,
                    "Hash_SHA-1": sha1,
                    "Extension": ext
                })
            else:
                md5, sha1 = get_file_hashes(abs_path)
                ext = get_file_extension(abs_path)
                not_webshell_files.append({
                    "path": abs_path,
                    "date": file_date,
                    "Hash_MD5": md5,
                    "Hash_SHA-1": sha1,
                    "Extension": ext
                })
        except Exception as e:
            print(f"Unable to detect {abs_path}: {e}")
            unable_files.append({
                "path": abs_path,
                "comment": str(e),
                "date": get_file_creation_date(abs_path)
            })
    elif os.path.isdir(file_path):
        total_files_found = scan_directory(file_path, predicter, webshell_files, not_webshell_files, unable_files, log_lines)

    scan_time = datetime.datetime.now().strftime("%d/%m/%Y-%H:%M:%S")

    # Prepare log in the requested format
    log_dict = {
        "TotalFilesFound": total_files_found,
        "PotentialWebshells": len(webshell_files),
        "NotWebshell": len(not_webshell_files),
        "TotalFilesIgnored": len(unable_files),
        "UnreadableFile": 0,
        "WebshellPaths": webshell_files,  # Now a list of dicts with all required fields
        "NotWebshellPaths": not_webshell_files,
        "FilesIgnoredPath": [
            {"path": f["path"], "comment": f["comment"]}
            for f in unable_files
        ],
        "UnreadableFilePath": [],
        "ScanTime": scan_time
    }

    # Write log to JSON file
    log_file = "scan_log.json"
    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(log_dict, f, indent=4, ensure_ascii=False)
    print(f"Prediction results saved to {log_file}")