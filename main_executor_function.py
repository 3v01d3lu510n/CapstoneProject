import os
from entropy_analyzer_functions import EntropyAnalyzer # Import the class

def main():
    directory = input("Enter the directory path to scan: ").strip()

    # Set your entropy thresholds (min, max) for each index
    # These can be adjusted based on the type of files you are analyzing
    # For general text/code:
    # InfoEntropy: Highly random (encrypted/compressed) files are >4. Plain text is lower.
    # SpecialCharEntropy: Code might have higher special char entropy than plain text.
    # QuoteEntropy: Files with many string literals (e.g., JSON, some code) might have higher quote entropy.
    info_entropy_threshold = (0.0, 4.0)      
    special_entropy_threshold = (0.0, 0.32)   
    quote_entropy_threshold = (0.0, 0.085)     

    analyzer = EntropyAnalyzer(info_entropy_threshold, special_entropy_threshold, quote_entropy_threshold)
    
    if not os.path.isdir(directory):
        print("Invalid directory path.")
        return

    print(f"Scanning directory: {directory}...")
    results = analyzer.scan_directory(directory)

    if not results:
        print("No suspicious files found.")
        return

    output_file_name = 'entropy_analysis_results.txt'
    try:
        with open(output_file_name, 'w', encoding='utf-8') as out:
            print("\n--- Suspicious Files Found ---")
            for line in results:
                print(line)
                out.write(line + '\n')
        print(f"\nAnalysis complete. Results saved to {output_file_name}")
    except IOError:
        print(f"Error: Could not write results to {output_file_name}")
        print("\n--- Suspicious Files Found ---")
        for line in results:
            print(line)
        
if __name__ == "__main__":
    main()