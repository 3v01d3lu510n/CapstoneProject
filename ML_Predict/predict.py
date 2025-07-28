import os
import time
import json
import joblib
import pandas as pd
from typing import List
import concurrent.futures
import Imports.zipfile as zip_utils
import Imports.result as result_utils
import Entropy, DataCharacteristics, tfidf_calculator

class WebshellPredicter:
    
    entropyAnalyzer = Entropy.EntropyAnalyzer()
    dataCharacteristics = DataCharacteristics.ASTAnalyzer()
    tfidfCalculator = tfidf_calculator.TFIDFCalculator()
    MODEL_PATH = os.path.join(os.path.dirname(__file__), 'random_forest_classifier.pkl')
    model = joblib.load(MODEL_PATH)
    
    def __init__(self):
        pass
    
    def get_entropies(self, file_bytes) -> float:
        return self.entropyAnalyzer.get_file_entropies(file_bytes)
    
    def get_data_characteristics_flag(self, file_bytes) -> int:
        return self.dataCharacteristics.evaluate_file_characteristics(file_bytes)
    
    def get_tfidf_result(self, file_path: str) -> List[float]:
        return self.tfidfCalculator.get_tfidf_result(file_path)
        
    def get_file_features(self, file_path: str) -> List[float]:
        file_bytes = open(file_path, 'rb')
        try:
            entropies = self.get_entropies(file_path)
            characteristics_flag = self.get_data_characteristics_flag(file_bytes)
            tfidf_result = self.get_tfidf_result(file_path)
        
            features = [
                entropies['info_entropy'],
                entropies['special_entropy'],
                entropies['quote_entropy'],
                characteristics_flag
            ] + tfidf_result
        except Exception:
            return None
        return features
    
def load_target_files(target_path):
    # Get list of file to scan from yara JSON logs
    if not os.path.isfile(target_path):
        print(f"Invalid target path: {target_path}")
        return []
    
    with open(target_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    target_files = data.get("Files no detect", [])
    detected_files = data.get("Detected", [])
    return target_files, detected_files
    
def yara_scan_and_log():
    yara_log_file = os.path.join("logs", "log_yara.json")
    target_files, detected_files = load_target_files(yara_log_file)
    scan_files_and_log(target_files, detected_files)
    os.remove(yara_log_file)
    
def scan_files_and_log(files: List, detected_files=[]):
    predicter = WebshellPredicter()
    webshell_files = detected_files
    not_webshell_files = []
    unable_files = []
    start_time = time.time()
    
    def safe_extract(file_path):
        try:
            features = predicter.get_file_features(file_path)
            if features:
                return (file_path, features)
            else:
                return (file_path, None)
        except Exception:
            return (file_path, None)
        
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(safe_extract, files))    

    valid_features = []
    valid_file_paths = []
    for file_path, features in results:
        if features is None:
            unable_files.append(file_path)
        else:
            valid_features.append(features)
            valid_file_paths.append(file_path)

    features_names = ['InfoEntropy', 'SpecialCharEntropy', 'QuoteEntropy', 'characteristics_flag'] + \
                        [f'tfidf_{i}' for i in range(len(valid_features[0]) - 4)] if valid_features else []
                        
    if valid_features:
        features_df = pd.DataFrame(valid_features, columns=features_names)
        predictions = predicter.model.predict(features_df)
        for prediction, file_path in zip(predictions, valid_file_paths):
            if prediction == 1:
                webshell_files.append(file_path)
            elif prediction == 0:
                not_webshell_files.append(file_path)
    
    end_time = time.time()
    print(f"Scanned in {end_time - start_time:.2f} seconds")
    print("-----Scan Summary-----")
    print(f"TotalFilesFound: {len(webshell_files) + len(not_webshell_files) + len(unable_files)}")
    print("-----Results Summary-----")
    print(f"PotentialWebshells: {len(webshell_files)}")
    print(f"NotWebshell: {len(not_webshell_files)}")
    print(f"TotalFilesIgnored: {len(unable_files)}")
    print("-----Output Summary-----")
    result_utils.create_log_file(len(files), webshell_files, not_webshell_files, unable_files)
    result_utils.create_summary_file(len(files), webshell_files, unable_files)
    zip_utils.zip_all_malicious_files(webshell_files)
    
def ml_scan_and_log(path):
    if os.path.isfile(path):
        files = [os.path.abspath(path)]
    elif os.path.isdir(path):
        files = [os.path.join(root, f) for root, dirs, fs in os.walk(path) for f in fs]
    else:
        print(f"Invalid path: {path}")
        return
    scan_files_and_log(files)

