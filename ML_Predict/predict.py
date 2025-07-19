import Entropy, DataCharacteristics, tfidf_calculator
import os
from typing import List
import pandas as pd
import joblib
import datetime
import Imports.result as result_utils
import time
import concurrent.futures

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
            entropies = self.get_entropies(file_bytes)
            characteristics_flag = self.get_data_characteristics_flag(file_bytes)
            tfidf_result = self.get_tfidf_result(file_path)
        
            features = [
                entropies['info_entropy'],
                entropies['special_entropy'],
                entropies['quote_entropy'],
                characteristics_flag
            ] + tfidf_result
        except Exception as e:
            return None
        return features
    
    def predict_file(self, file_path: str):
        features = self.get_file_features(file_path)
        if not features:
            return None
        
        features_names = ['InfoEntropy', 'SpecialCharEntropy', 'QuoteEntropy', 'characteristics_flag'] + [f'tfidf_{i}' for i in range(len(features) - 4)]
        features_df = pd.DataFrame([features], columns=features_names)
        prediction = self.model.predict(features_df)
        
        return prediction[0]
    
    def predict_directory(self, directory: str):
        file_paths = []
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_paths.append(os.path.join(root, file))

        webshell_files = []
        not_webshell_files = []
        unable_files = []
        total_files_found = len(file_paths)

        def safe_extract(file_path):
            try:
                features = self.get_file_features(file_path)
                if features:
                    return (file_path, features)
                else:
                    return (file_path, None)
            except Exception:
                return (file_path, None)

        # Parallel feature extraction
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(safe_extract, file_paths))

        # Separate features and handle failures
        valid_features = []
        valid_file_paths = []
        for file_path, features in results:
            if features is None:
                unable_files.append(file_path)
            else:
                valid_features.append(features)
                valid_file_paths.append(file_path)

        if not valid_features:
            return total_files_found, [], [], unable_files

        features_names = ['InfoEntropy', 'SpecialCharEntropy', 'QuoteEntropy', 'characteristics_flag'] + \
                        [f'tfidf_{i}' for i in range(len(valid_features[0]) - 4)]

        features_df = pd.DataFrame(valid_features, columns=features_names)
        predictions = self.model.predict(features_df)

        for prediction, file_path in zip(predictions, valid_file_paths):
            if prediction == 1:
                webshell_files.append(file_path)
            elif prediction == 0:
                not_webshell_files.append(file_path)

        return total_files_found, webshell_files, not_webshell_files, unable_files
    
def scan_and_log(path):
    webshell_files = []
    not_webshell_files = []
    unable_files = []
    total_files_found = 0
    predicter = WebshellPredicter()
    start_time = time.time()
    if os.path.isfile(path):
        try:
            abs_path = os.path.abspath(path)
            total_files_found = 1
            result = predicter.predict_file(abs_path)
            if result is None:
                unable_files.append(abs_path)
            elif result == 1:
                webshell_files.append(abs_path)
            else:
                not_webshell_files.append(abs_path)
        except Exception as e:
            unable_files.append(path)
    elif os.path.isdir(path):
        abs_path = os.path.abspath(path)
        total_files_found, webshell_files, not_webshell_files, unable_files = predicter.predict_directory(abs_path)
    else:
        print(f"Invalid path: {path}")
        return
    end_time = time.time()
    scan_time = datetime.datetime.now().strftime("%d/%m/%Y-%H:%M:%S")
    print("Scanning...")
    print(f"Scanned in {end_time - start_time:.2f} seconds")
    print("-----Results summary-----")
    print(f"TotalFilesFound: {total_files_found}")
    print(f"PotentialWebshells: {len(webshell_files)}")
    print(f"NotWebshell: {len(not_webshell_files)}")
    print(f"TotalFilesIgnored: {len(unable_files)}")
    print(f"ScanTime: {scan_time}\n")
    # print("-----Webshells detected-----")
    # for f in webshell_files:
    #     print(f"Webshell detected in {f}")

    result_utils.create_log_file(total_files_found, webshell_files, not_webshell_files, unable_files)
    result_utils.create_summary_file(total_files_found, webshell_files, unable_files)
        