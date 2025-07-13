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
        return self.entropyAnalyzer.analyze_file(file_path)
    
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
        
        # Predict using the model
        prediction = self.model.predict(features_df)
        
        return prediction[0]
    
    def predict_directory(self, directory_path: str):
        results = {}
        for root, dirs, files in os.walk(directory_path):
            for filename in files:
                file_path = os.path.join(root, filename)
                if os.path.isfile(file_path):
                    prediction = self.predict_file(file_path)
                    results[file_path] = 'Webshell' if prediction == 1 else 'Not a Webshell'
        return results
    
if __name__ == "__main__":
   
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file/directory_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    predicter = WebshellPredicter()
    
    if os.path.isfile(file_path):
        result = predicter.predict_file(file_path)
        print(f"Prediction for file {file_path}: {'Webshell' if result == 1 else 'Not a Webshell'}")

    if os.path.isdir(file_path):
        results = predicter.predict_directory(file_path)
        for path, prediction in results.items():
            print(f"Prediction for file {path}: {prediction}")