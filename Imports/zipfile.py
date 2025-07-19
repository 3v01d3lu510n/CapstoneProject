import os
import zipfile
from datetime import datetime
from typing import List
from pathlib import Path

def ensure_output_folder(folder_name: str = "output") -> Path:
    folder_path = Path(folder_name)
    folder_path.mkdir(parents=True, exist_ok=True)
    return folder_path.resolve()

def zip_all_malicious_files(detected_files: List[str], output_folder: str = "output", base_folder: str = ""):
    output_path = ensure_output_folder(output_folder)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    zip_file_name = output_path / f"Webshells_{timestamp}.zip"

    try:
        with zipfile.ZipFile(zip_file_name, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in detected_files:
                if os.path.exists(file_path):
                    arcname = os.path.relpath(file_path, start=base_folder) if base_folder else os.path.basename(file_path)
                    zipf.write(file_path, arcname=arcname)
        print(f"Zipped detected files to: {zip_file_name}")
    except Exception as e:
        print(f"Failed to zip files: {e}")
