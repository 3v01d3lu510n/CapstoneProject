import math
from collections import Counter

class EntropyAnalyzer:
    def __init__(
        self
    ):
        pass  # Placeholder for any initialization if needed

    def calculate_info_entropy(self, file_bytes):
        size = len(file_bytes)
        if size == 0:
            return 0.0
        freq = Counter(file_bytes)
        entropy = 0.0
        for count in freq.values():
            p = count / size
            entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _is_chinese_char(char):
        # Method to check for Chinese characters
        return '\u4e00' <= char <= '\u9fff'

    def calculate_special_char_entropy(self, text):
        # Text is already a decoded string
        content_no_space = (c for c in text if c != ' ')
        chars = list(content_no_space)
        k = len(chars)
        if k == 0:
            return 0.0
        a = sum(not (c.isalnum() or self._is_chinese_char(c)) for c in chars)
        b = sum(not self._is_chinese_char(c) for c in chars)
        Pa = a / k
        Pb = b / k
        entropy = 0.0
        if Pa > 0:
            entropy -= Pa * math.log2(Pa)
        if Pb > 0:
            entropy -= Pb * math.log2(Pb)
        return entropy

    def calculate_quote_entropy(self, text):
        # Text is already a decoded strings
        a_count = b_count = k = 0
        for c in text:
            if c != ' ':
                k += 1
                if c == "'":
                    a_count += 1
                elif c == '"':
                    b_count += 1
        if k == 0:
            return 0.0
        p_a = a_count / k
        p_b = b_count / k
        entropy_a = -p_a * math.log2(p_a) if p_a > 0 else 0.0
        entropy_b = -p_b * math.log2(p_b) if p_b > 0 else 0.0
        return entropy_a + entropy_b

    def get_file_entropies(self, file_path):
        try:
            with open(file_path, "rb") as f:
                file_bytes = f.read()
        except Exception as e:
            print(f"[DEBUG] unreadable for {file_path}: {e}")
            return None
        text = file_bytes.decode('utf-8', errors='ignore')
        entropies = dict()
        entropies['info_entropy'] = self.calculate_info_entropy(file_bytes)
        entropies['special_entropy'] = self.calculate_special_char_entropy(text)
        entropies['quote_entropy'] = self.calculate_quote_entropy(text)
        return entropies
