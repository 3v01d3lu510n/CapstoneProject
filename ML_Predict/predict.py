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
    MODEL_PATH = os.path.join(os.path.dirname(__file__), 'random_forest_classifier.pkl')
    model = joblib.load(MODEL_PATH)
    
    def __init__(self):
        self.entropyAnalyzer = Entropy.EntropyAnalyzer()
        self.dataCharacteristics = DataCharacteristics.ASTAnalyzer()
        self.tfidfCalculator = tfidf_calculator.TFIDFCalculator()
        self.model = joblib.load(self.MODEL_PATH)
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
    
    def get_file_hashes(self, file_path):
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

    def get_file_extension(self, file_path):
        return '.' + os.path.splitext(file_path)[1].lstrip('.').lower()

    def get_file_creation_date(self, file_path):
        """Return the creation date of the file as dd/mm/YYYY."""
        try:
            ctime = os.path.getctime(file_path)
            return datetime.datetime.fromtimestamp(ctime).strftime("%d/%m/%Y")
        except Exception:
            return ""

    def scan_directory(self, dir_path, predicter, webshell_files, not_webshell_files, unable_files, log_lines):
        total_files = 0
        for root, _, files in os.walk(dir_path):
            for file in files:
                abs_path = os.path.abspath(os.path.join(root, file))
                total_files += 1
                try:
                    result = predicter.predict_file(abs_path)
                    label = 'Webshell' if result == 1 else 'Not a Webshell'
                    log_lines.append(f"Prediction for file {abs_path}: {label}")
                    file_date = self.get_file_creation_date(abs_path)
                    if label == 'Webshell':
                        md5, sha1 = self.get_file_hashes(abs_path)
                        ext = self.get_file_extension(abs_path)
                        webshell_files.append({
                            "path": abs_path,
                            "date": file_date,
                            "Hash_MD5": md5,
                            "Hash_SHA-1": sha1,
                            "Extension": ext
                        })
                    else:
                        md5, sha1 = self.get_file_hashes(abs_path)
                        ext = self.get_file_extension(abs_path)
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
                        "date": self.get_file_creation_date(abs_path)
                    })
        return total_files

    def scan_and_log(self, path):
        log_lines = []
        webshell_files = []
        not_webshell_files = []
        unable_files = []
        total_files_found = 0

        if os.path.isfile(path):
            abs_path = os.path.abspath(path)
            total_files_found = 1
            try:
                result = self.predict_file(abs_path)
                label = 'Webshell' if result == 1 else 'Not a Webshell'
                log_lines.append(f"Prediction for file {abs_path}: {label}")
                file_date = self.get_file_creation_date(abs_path)
                md5, sha1 = self.get_file_hashes(abs_path)
                ext = self.get_file_extension(abs_path)
                entry = {
                    "path": abs_path,
                    "date": file_date,
                    "Hash_MD5": md5,
                    "Hash_SHA-1": sha1,
                    "Extension": ext
                }
                if label == 'Webshell':
                    webshell_files.append(entry)
                else:
                    not_webshell_files.append(entry)
            except Exception as e:
                print(f"Unable to detect {abs_path}: {e}")
                unable_files.append({
                    "path": abs_path,
                    "date": self.get_file_creation_date(abs_path)
                })
        elif os.path.isdir(path):
            total_files_found = self.scan_directory(
                path, self, webshell_files, not_webshell_files, unable_files, log_lines
            )
        else:
            print(f"Invalid path: {path}")
            return

        scan_time = datetime.datetime.now().strftime("%d/%m/%Y-%H:%M:%S")
        log_dict = {
            "TotalFilesFound": total_files_found,
            "PotentialWebshells": len(webshell_files),
            "NotWebshell": len(not_webshell_files),
            "TotalFilesIgnored": len(unable_files),
            "WebshellPaths": webshell_files,
            "NotWebshellPaths": not_webshell_files,
            "FilesIgnoredPath": [
                {"path": f["path"], "date": f["date"]}
                for f in unable_files
            ],
            "ScanTime": scan_time
        }

        log_dir = "log"
        os.makedirs(log_dir, exist_ok=True)
        existing_logs = [f for f in os.listdir(log_dir) if f.startswith("scan_log_") and f.endswith(".json")]
        log_count = len(existing_logs) + 1
        log_file = os.path.join(log_dir, f"scan_log_{log_count}.json")

        with open(log_file, "w", encoding="utf-8") as f:
            json.dump(log_dict, f, indent=4, ensure_ascii=False)
        print(f"Prediction results saved to {log_file}")

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file/directory_path>")
        sys.exit(1)

    path = sys.argv[1]
    predicter = WebshellPredicter()
    predicter.scan_and_log(path)