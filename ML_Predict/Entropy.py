import sys
import math

class EntropyAnalyzer:
    def __init__(
        self
    ):
        pass  # Placeholder for any initialization if needed

    def calculate_info_entropy(self, file_path):
        # Calculates the Shannon entropy of a file based on byte frequency
        freq = {}
        size = 0
        try:
            with open(file_path, 'rb') as f:
                while True:
                    byte = f.read(1)
                    if not byte:
                        break
                    freq[byte] = freq.get(byte, 0) + 1
                    size += 1
        except Exception as e:
            print(f"[DEBUG] info_entropy unreadable for {file_path}: {e}")
            return None  # Return None if file can't be read

        if size == 0:
            return 0.0

        entropy = 0.0
        for count in freq.values():
            p = count / size
            if p > 0: # Avoid math.log2(0)
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _is_chinese_char(char):
        # Method to check for Chinese characters
        return '\u4e00' <= char <= '\u9fff'

    def calculate_special_char_entropy(self, file_path):
        # Calculates special character entropy
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"[DEBUG] special_entropy unreadable for {file_path}: {e}")
            return None  # Return None if file can't be read

        # Length of characters of file (non space)
        content_no_space = content.replace(" ", "")
        k = len(content_no_space)

        if k == 0:
            return 0.0

        # a = number of characters that are not letters (a-zA-Z), numbers (0-9), or Chinese characters
        a_chars = [
            c for c in content_no_space 
            if not (c.isalnum() or self._is_chinese_char(c))
        ]
        a = len(a_chars)

        # b = number of characters that are not Chinese characters
        b_chars = [c for c in content_no_space if not self._is_chinese_char(c)]
        b = len(b_chars)

        Pa = a / k if k > 0 else 0.0
        Pb = b / k if k > 0 else 0.0
        
        entropy = 0.0
        # Calculate entropy contributions, avoiding log(0)
        # Formula: -(Pa * log2(Pa) + Pb * log2(Pb))
        if Pa > 0:
            entropy -= Pa * math.log2(Pa)
        if Pb > 0:
            entropy -= Pb * math.log2(Pb)
            
        return entropy


    def calculate_quote_entropy(self, file_path):
        # Calculates quote entropy
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            print(f"[DEBUG] quote_entropy unreadable for {file_path}: {e}")
            return None  # Return None if file can't be read

        # Count character ' and "
        a_count = content.count("'")  # Count of character '
        b_count = content.count('"')  # Count of character "

        # Length of characters of file (non space)
        content_no_space = content.replace(" ", "")
        k = len(content_no_space)
        
        if k == 0:
            return 0.0
            
        p_a = a_count / k
        p_b = b_count / k
        
        entropy_a = 0.0
        entropy_b = 0.0
        
        if p_a > 0:
            entropy_a = -p_a * math.log2(p_a)
        if p_b > 0:
            entropy_b = -p_b * math.log2(p_b)
            
        entropy = entropy_a + entropy_b
        return entropy

    def get_file_entropies(self, file_path):
        # Analyzes a file for its various entropy values
        entropies = dict()
        info_entropy = self.calculate_info_entropy(file_path)
        entropies['info_entropy'] = info_entropy
        special_entropy = self.calculate_special_char_entropy(file_path)
        entropies['special_entropy'] = special_entropy
        quote_entropy = self.calculate_quote_entropy(file_path)
        entropies['quote_entropy'] = quote_entropy
        return entropies

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file_path>")
        sys.exit(1)
        
    file_path = sys.argv[1]
    entropy_analyzer = EntropyAnalyzer()
    
    entropies = entropy_analyzer.get_file_entropies(file_path)
    if entropies:
        print(f"Entropy values for {file_path}:")
        for key, value in entropies.items():
            print(f"{key}: {value}")
    else:
        print(f"No entropy values calculated for {file_path}.")