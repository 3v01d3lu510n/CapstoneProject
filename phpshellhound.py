import sys
import os
import re
import csv
import json
import zipfile
import datetime
import time
from optparse import OptionParser

from entropy_analyzer_functions import EntropyAnalyzer 
from hash_calculation_functions import FileHashCalculator

# === Create a folder if it does not exist ===
def ensure_folder(folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

# === Result object functions for file scan ===
def create_result_object(
    path,
    info_entropy,
    special_entropy,
    quote_entropy,
    stdev,
    hash_sha256,
    hash_md5,
    last_modified,
    detection_method,
    evaluation,
):
    result = {
        "FilePath": path,
        "Entropy": {
            "InfoEntropy": info_entropy,
            "SpecialCharEntropy": special_entropy,
            "QuoteEntropy": quote_entropy,
        },
        "StDev": stdev,
        "Hash": {
            "SHA256": hash_sha256,
            "MD5": hash_md5
        },
        "LastModified": last_modified,
        "DetectionMethod": detection_method,
        "Evaluation": evaluation
    }
    return result

# === Zip detected webshell files into one archive in Webshell_detect folder ===
def zip_webshell_files(webshell_paths, zip_folder="Webshell_detect"):
    ensure_folder(zip_folder)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_file_path = os.path.join(zip_folder, f"webshells_{timestamp}.zip")
    skipped = []
    with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for f in webshell_paths:
            if not os.path.exists(f):
                print(f"[ZIP] Skipped (not found): {f}")
                skipped.append(f)
                continue
            arcname = os.path.basename(f)
            # If file name exists in archive, append number to avoid conflicts
            if arcname in zipf.namelist():
                base, ext = os.path.splitext(arcname)
                i = 1
                while f"{base}_{i}{ext}" in zipf.namelist():
                    i += 1
                arcname = f"{base}_{i}{ext}"
            try:
                zipf.write(f, arcname=arcname)
            except Exception as e:
                print(f"[ZIP] Skipped (error): {f} | {e}")
                skipped.append(f)
    print(f"[+] Webshell clone files zipped to: {zip_file_path}")
    if skipped:
        print(f"[ZIP] Skipped {len(skipped)} files (see above for reasons).")

# === Scan directory for files and analyze entropy ===
def scan_by_entropy(directory, file_regex):
    analyzer = EntropyAnalyzer()
    hash_calc = FileHashCalculator()
    results = []
    webshell_paths = []
    total_files = 0
    total_ignored = 0

    for root, dirs, files in os.walk(directory):
        for name in files:
            if file_regex:
                matched = False
                for ext in file_regex.split('|'):
                    ext = ext if ext.startswith('.') else '.' + ext
                    if name.lower().endswith(ext.lower()):
                        matched = True
                        break
                if not matched:
                    total_ignored += 1
                    continue
            file_path = os.path.join(root, name)
            total_files += 1

            info_e, special_e, quote_e = analyzer.analyze_file(file_path)
            evaluation = analyzer.evaluate(info_e, special_e, quote_e)

            if evaluation.startswith("Suspicious") or evaluation.startswith("Unreadable"):
                # Only save result if the file is detected as suspicious or unreadable
                hash_sha256 = hash_calc.calculate_sha256(file_path)
                hash_md5 = hash_calc.calculate_md5(file_path)
                last_modified = datetime.datetime.fromtimestamp(
                    os.path.getmtime(file_path), tz=datetime.timezone.utc
                ).strftime('%Y-%m-%dT%H:%M:%SZ')
                stdev = 0
                detection_method = "EntropyAnalyzer"
                result = create_result_object(
                    file_path,
                    round(info_e, 6) if info_e is not None else None,
                    round(special_e, 6) if special_e is not None else None,
                    round(quote_e, 6) if quote_e is not None else None,
                    stdev,
                    hash_sha256,
                    hash_md5,
                    last_modified,
                    detection_method,
                    evaluation
                )
                results.append(result)
                webshell_paths.append(file_path)
                print(f"[Webshell] {file_path} - {evaluation}")
    return results, webshell_paths, total_files, total_ignored

# === Scan directory for files and detect webshell by another method (In future, can extend more modules here) ===
# def scan_by_another_method(directory, file_regex):
    # Placeholder for another detection method
    # pass
# ===END Detect function===

# === Write results to CSV file ===
def write_csv(results, csv_file):
    headers = [
        "FilePath", 
        "InfoEntropy", 
        "SpecialCharEntropy", 
        "QuoteEntropy",
        "SHA256", 
        "MD5", 
        "LastModified", 
        "DetectionMethod", 
        "Evaluation"
    ]
    with open(csv_file, 'w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for r in results:
            writer.writerow([
                r['FilePath'],
                r['Entropy']['InfoEntropy'],
                r['Entropy']['SpecialCharEntropy'],
                r['Entropy']['QuoteEntropy'],
                r['Hash']['SHA256'],
                r['Hash']['MD5'],
                r['LastModified'],
                r['DetectionMethod'],
                r['Evaluation']
            ])

# === Write results to TXT file ===
def write_txt(results, txt_file):
    with open(txt_file, 'w', encoding='utf-8') as f:
        for r in results:
            f.write(f"File: {r['FilePath']}\n")
            f.write(f"  InfoEntropy: {r['Entropy']['InfoEntropy']}\n")
            f.write(f"  SpecialCharEntropy: {r['Entropy']['SpecialCharEntropy']}\n")
            f.write(f"  QuoteEntropy: {r['Entropy']['QuoteEntropy']}\n")
            f.write(f"  SHA256: {r['Hash']['SHA256']}\n")
            f.write(f"  MD5: {r['Hash']['MD5']}\n")
            f.write(f"  LastModified: {r['LastModified']}\n")
            f.write(f"  DetectionMethod: {r['DetectionMethod']}\n")
            f.write(f"  Evaluation: {r['Evaluation']}\n")
            f.write("-" * 60 + "\n")

# === Write results to JSON file ===
def write_json(results, json_file):
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

# === Write summary scanned log file ===
def write_summary(summary, log_file):
    with open(log_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=4, ensure_ascii=False)

# === Main Entry Point ===
if __name__ == "__main__":
    
    print('''
        =========================================================
         ___ _  _ ___  ___ _        _ _ _  _                  _ 
        | _ \ || | _ \/ __| |_  ___| | | || |___ _  _ _ _  __| |
        |  _/ __ |  _/\__ \ ' \/ -_) | | __ / _ \ || | ' \/ _` |
        |_| |_||_|_|  |___/_||_\___|_|_|_||_\___/\_,_|_||_\__,_|
                                                                                    
                Tool is being developed by IAP491_G5 
        =========================================================
        ''')
    
    parser = OptionParser(usage="usage: %prog [options] <directory> <OPTIONAL: filename regex/extensions>", version="%prog 1.0")

    parser.add_option("-c", "--csv", 
                      dest="csv_file", 
                      default=None, 
                      help="Write webshell results to CSV file", 
                      metavar="FILECSV")
    parser.add_option("-t", "--txt", 
                      dest="txt_file", 
                      default=None, 
                      help="Write webshell results to TXT file", 
                      metavar="FILETXT")
    parser.add_option("-j", "--json", 
                      dest="json_file", 
                      default=None, 
                      help="Write webshell results to JSON file", 
                      metavar="FILEJSON")
    parser.add_option("-a", "--all", 
                      action="store_true", 
                      dest="use_all_method_detect", 
                      default=False, 
                      help="Use all detect modules (recommended)")
    parser.add_option("-e", "--entropy", 
                      action="store_true", 
                      dest="use_entropy", 
                      default=False, 
                      help="Use entropy analysis (EntropyAnalyzer only)")
    parser.add_option("-A", "--auto", 
                      action="store_true", 
                      dest="auto_ext", 
                      default=False, 
                      help="Auto file extension filter (.php, .txt, etc)")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        sys.exit(1)
        
    directory = args[0]
    if not os.path.isdir(directory):
        print(f"Invalid directory: {directory}")
        sys.exit(1)

    if options.auto_ext:
        file_regex = "php|txt"  # Default auto extensions, can add more if needed
    elif len(args) > 1:
        file_regex = args[1]
    else:
        file_regex = None

    # --- Start scan ---
    ensure_folder("result")
    ensure_folder("logs")
    ensure_folder("Webshell_detect")

    time_start = time.time()

    all_results = []
    all_paths = []
    total_files = 0
    total_ignored = 0

    # --- Use all modules detect (In the future, can add other modules here for --all) ---
    if options.use_all_method_detect:
        entropy_results, entropy_paths, entropy_total_files, entropy_ignored = scan_by_entropy(directory, file_regex)
        all_results.extend(entropy_results)
        all_paths.extend(entropy_paths)
        total_files += entropy_total_files # Error if added more modules here, so only use entropy for now, will update later
        total_ignored += entropy_ignored # Error if added more modules here, so only use entropy for now, will update later
        
    # --- Only use entropy analysis module to detected webshell ---
    elif options.use_entropy:
        entropy_results, entropy_paths, entropy_total_files, entropy_ignored = scan_by_entropy(directory, file_regex)
        all_results.extend(entropy_results)
        all_paths.extend(entropy_paths)
        total_files += entropy_total_files
        total_ignored += entropy_ignored
    # --- If no specific method is selected, default to entropy analysis ---

    # --- Deduplicate results ---
    dedup = {}
    for r in all_results:
        dedup[r['FilePath']] = r
    final_results = list(dedup.values())
    webshell_paths = list(set(all_paths))

    # --- Output results ---
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if options.use_all_method_detect or options.auto_ext: 
        result_file = os.path.join("result", f"scan_results_{timestamp}.json")
        summary_file = os.path.join("logs", f"scan_summary_{timestamp}.json")
    else:
        result_file = options.json_file or "result/scan_results.json" # Will fix in future
        summary_file = options.txt_file or "logs/scan_summary.json" # Will fix in future

    if options.csv_file:
        write_csv(final_results, os.path.join("result", options.csv_file))
        print(f"Webshell results written to CSV: result/{options.csv_file}")
    if options.txt_file:
        write_txt(final_results, os.path.join("result", options.txt_file))
        print(f"Webshell results written to TXT: result/{options.txt_file}")
    if options.json_file:
        write_json(final_results, os.path.join("result", options.json_file))
        print(f"Webshell results written to JSON: result/{options.json_file}")

    # If using auto or all options, default to saving results in result/
    # if (options.use_all_method_detect or options.auto_ext) and not (options.csv_file or options.txt_file or options.json_file):
    #    write_json(final_results, result_file)
    #    print(f"Webshell results written to: {result_file}")

    # --- Write information summary log ---
    time_end = time.time()
    summary = {
        "TotalFilesScanned": total_files,
        "TotalFilesIgnored": total_ignored,
        "PotentialWebshells": len(webshell_paths),
        "WebshellPaths": webshell_paths,
        "Scan Time": f"{time_end - time_start:.2f} seconds"
    }
    write_summary(summary, summary_file)
    print(f"Summary written to: {summary_file}")

    # --- Clone & zip detected webshell files ---
    if webshell_paths:
        zip_webshell_files(webshell_paths)
    else:
        print("[+] No webshell files found for zipping.")
