import Entropy, DataCharacteristics, tfidf_calculator
import sys, os
from typing import List
import pandas as pd
import joblib

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
    
    def predict_directory(self, directory_path: str):
        results = {}
        for root, dirs, files in os.walk(directory_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                abs_path = os.path.abspath(file_path)
                if os.path.isfile(abs_path):
                    prediction = self.predict_file(abs_path)
                    if prediction is None:
                        results[abs_path] = 'Unable to predict'
                    results[abs_path] = 'Webshell' if prediction == 1 else 'Not a Webshell'
        return results

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

    try: 
        if os.path.isfile(file_path):
            abs_path = os.path.abspath(file_path)
            result = predicter.predict_file(abs_path)
            label = 'Webshell' if result == 1 else 'Not a Webshell'
            print(f"Prediction for file {abs_path}: {label}")
            log_lines.append(f"Prediction for file {abs_path}: {label}")
            if label == 'Webshell':
                webshell_files.append(abs_path)
            else:
                not_webshell_files.append(abs_path)

        elif os.path.isdir(file_path):
            results = predicter.predict_directory(file_path)
            for path, prediction in results.items():
                log_lines.append(f"Prediction for file {path}: {prediction}")
                if prediction == 'Webshell':
                    webshell_files.append(path)
                elif prediction == 'Not a Webshell':
                    not_webshell_files.append(path)
                else:
                    unable_files.append(path)
    except Exception as e:
        print(f"Unable to detect {file_path}")
        sys.exit(1)

    # Add summary to log
    summary = []
    summary.append(f"Summary:")
    summary.append(f"Webshell: {len(webshell_files)}")
    for f in webshell_files:
        summary.append(f"  {f}")
    summary.append(f"Not a Webshell: {len(not_webshell_files)}")
    for f in not_webshell_files:
        summary.append(f"  {f}")
    summary.append(f"Unable to predict: {len(unable_files)}")
    for f in unable_files:
        summary.append(f"  {f}")

    log_lines.extend(summary)
    print('\n'.join(summary))

    # Write log to file
    log_file = "prediction_log.txt"
    with open(log_file, "w", encoding="utf-8") as f:
        for line in log_lines:
            f.write(line + "\n")
    print(f"Prediction results saved to {log_file}")