import hashlib

class FileHashCalculator:
    @staticmethod
    def calculate_sha256(filepath):
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as file:
                for chunk in iter(lambda: file.read(4096), b""):
                    sha256_hash.update(chunk)
        except FileNotFoundError:
            return f"File not found: {filepath}"
        except Exception as e:
            return f"An error occurred: {e}"
        return sha256_hash.hexdigest()

    @staticmethod
    def calculate_md5(filepath):
        md5_hash = hashlib.md5()
        try:
            with open(filepath, "rb") as file:
                for chunk in iter(lambda: file.read(4096), b""):
                    md5_hash.update(chunk)
        except FileNotFoundError:
            return f"File not found: {filepath}"
        except Exception as e:
            return f"An error occurred: {e}"
        return md5_hash.hexdigest()