import os
import zipfile
from datetime import datetime
from typing import List

def zip_all_malicious_files(detected_files: List[str], output_folder: str = "output", base_folder: str = ""):
    if not detected_files:
        print("No files to zip.")
        return

    os.makedirs(output_folder, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    zip_file_name = os.path.join(output_folder, f"Webshells_{timestamp}.zip")

    try:
        with zipfile.ZipFile(zip_file_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in detected_files:
                if os.path.exists(file_path):
                    arcname = os.path.relpath(file_path, start=base_folder) if base_folder else os.path.basename(file_path)
                    zipf.write(file_path, arcname=arcname)
        print(f"Zipped detected files to: {zip_file_name}")
    except Exception as e:
        print(f"Failed to zip files: {e}")
