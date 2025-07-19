import Entropy, DataCharacteristics, tfidf_calculator
import sys, os
from typing import List
import pandas as pd
import joblib
import datetime
import Imports.result as result_utils

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

def scan_and_log(path):
    webshell_files = []
    not_webshell_files = []
    unable_files = []
    total_files_found = 0
    predicter = WebshellPredicter()
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
        for root, dirs, files in os.walk(abs_path):
            for file in files:
                file_path = os.path.join(root, file)
                total_files_found += 1
                try:
                    result = predicter.predict_file(file_path)
                    if result is None:
                        unable_files.append(file_path)
                    elif result == 1:
                        webshell_files.append(file_path)
                    else:
                        not_webshell_files.append(file_path)
                except Exception as e:
                    unable_files.append(file_path)
    else:
        print(f"Invalid path: {path}")
        return
    scan_time = datetime.datetime.now().strftime("%d/%m/%Y-%H:%M:%S")
    print("Scanning...")
    print("-----Results summary-----")
    print(f"TotalFilesFound: {total_files_found}")
    print(f"PotentialWebshells: {len(webshell_files)}")
    print(f"NotWebshell: {len(not_webshell_files)}")
    print(f"TotalFilesIgnored: {len(unable_files)}")
    print(f"ScanTime: {scan_time}\n")
    print("-----Webshells detected-----")
    for f in webshell_files:
        print(f"Webshell detected in {f}")

    result_utils.create_log_file(total_files_found, webshell_files, not_webshell_files, unable_files)
    result_utils.create_summary_file(total_files_found, webshell_files, unable_files)
        
if __name__ == "__main__":

    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file/directory_path>")
        sys.exit(1)

    path = sys.argv[1]
    scan_and_log(path)