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

def ensure_folder(folder_path):
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

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

# === Sửa đổi hàm này để hỗ trợ cả extension & nội dung và in kết quả chi tiết ra terminal ===
def scan_by_entropy(directory, file_regex=None, scan_php_content=False):
    analyzer = EntropyAnalyzer()
    hash_calc = FileHashCalculator()
    results = []
    webshell_paths = []
    ignored_paths = []
    unreadable_paths = []
    total_files = 0

    for root, dirs, files in os.walk(directory):
        for name in files:
            file_path = os.path.join(root, name)
            total_files += 1

            scan_this = False
            matched_ext = False
            matched_php = False

            if file_regex:
                for ext in file_regex.split('|'):
                    ext = ext if ext.startswith('.') else '.' + ext
                    if name.lower().endswith(ext.lower()):
                        matched_ext = True
                        break

            if scan_php_content:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        if '<?php' in f.read(4096):
                            matched_php = True
                except Exception:
                    unreadable_paths.append(file_path)
                    continue

            if scan_php_content and file_regex:
                scan_this = matched_ext or matched_php
            elif scan_php_content:
                scan_this = matched_php
            elif file_regex:
                scan_this = matched_ext
            else:
                scan_this = True

            if not scan_this:
                ignored_paths.append(file_path)
                continue

            info_e, special_e, quote_e = analyzer.analyze_file(file_path)
            evaluation = analyzer.evaluate(info_e, special_e, quote_e)

            if evaluation.startswith("Unreadable"):
                unreadable_paths.append(file_path)

            if evaluation.startswith("Suspicious") or evaluation.startswith("Unreadable"):
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
                if evaluation.startswith("Suspicious"):
                    webshell_paths.append(file_path)
                # In ra terminal chi tiết:
                print("="*60)
                print(f"File: {file_path}")
                print(f"  InfoEntropy: {result['Entropy']['InfoEntropy']}")
                print(f"  SpecialCharEntropy: {result['Entropy']['SpecialCharEntropy']}")
                print(f"  QuoteEntropy: {result['Entropy']['QuoteEntropy']}")
                print(f"  SHA256: {result['Hash']['SHA256']}")
                print(f"  MD5: {result['Hash']['MD5']}")
                print(f"  LastModified: {result['LastModified']}")
                print(f"  DetectionMethod: {result['DetectionMethod']}")
                print(f"  Evaluation: {result['Evaluation']}")
                print("="*60)
    total_ignored = len(ignored_paths)
    return results, webshell_paths, total_files, total_ignored, ignored_paths, unreadable_paths

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

def write_json(results, json_file):
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)

def write_summary(summary, log_file):
    with open(log_file, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=4, ensure_ascii=False)

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
    parser.add_option("-p", "--phpcontent",
                      action="store_true",
                      dest="scan_php_content",
                      default=False,
                      help="Scan files containing '<?php' regardless of extension")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        sys.exit(1)
    directory = args[0]
    if not os.path.isdir(directory):
        print(f"Invalid directory: {directory}")
        sys.exit(1)
    scan_php_content = options.scan_php_content
    file_regex = None
    if options.auto_ext:
        file_regex = "php|txt|jpg"
    elif len(args) > 1:
        file_regex = args[1]

    ensure_folder("result")
    ensure_folder("logs")
    ensure_folder("Webshell_detect")

    time_start = time.time()
    all_results = []
    all_paths = []
    all_ignored_paths = []
    all_unreadable_paths = []
    total_files = 0
    total_ignored = 0

    if options.use_all_method_detect:
        entropy_results, entropy_paths, entropy_total_files, entropy_ignored, ignored_paths, unreadable_paths = scan_by_entropy(directory, file_regex=file_regex, scan_php_content=scan_php_content)
        all_results.extend(entropy_results)
        all_paths.extend(entropy_paths)
        total_files += entropy_total_files
        total_ignored += entropy_ignored
        all_ignored_paths.extend(ignored_paths)
        all_unreadable_paths.extend(unreadable_paths)
    elif options.use_entropy:
        entropy_results, entropy_paths, entropy_total_files, entropy_ignored, ignored_paths, unreadable_paths = scan_by_entropy(directory, file_regex=file_regex, scan_php_content=scan_php_content)
        all_results.extend(entropy_results)
        all_paths.extend(entropy_paths)
        total_files += entropy_total_files
        total_ignored += entropy_ignored
        all_ignored_paths.extend(ignored_paths)
        all_unreadable_paths.extend(unreadable_paths)
    else:
        print("No detection method specified, defaulting to --entropy.")
        entropy_results, entropy_paths, entropy_total_files, entropy_ignored, ignored_paths, unreadable_paths = scan_by_entropy(directory, file_regex=file_regex, scan_php_content=scan_php_content)
        all_results.extend(entropy_results)
        all_paths.extend(entropy_paths)
        total_files += entropy_total_files
        total_ignored += entropy_ignored
        all_ignored_paths.extend(ignored_paths)
        all_unreadable_paths.extend(unreadable_paths)

    dedup = {}
    for r in all_results:
        dedup[r['FilePath']] = r
    final_results = list(dedup.values())
    webshell_paths = list(set(all_paths))

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_output_file = options.csv_file
    txt_output_file = options.txt_file
    json_output_file = options.json_file

    if not (csv_output_file or txt_output_file or json_output_file):
        csv_output_file = f"scan_results_{timestamp}.csv"
        print(f"No output format specified. Defaulting to CSV: result/{csv_output_file}")

    if csv_output_file:
        write_csv(final_results, os.path.join("result", csv_output_file))
        print(f"Webshell results written to CSV: result/{csv_output_file}")
    if txt_output_file:
        write_txt(final_results, os.path.join("result", txt_output_file))
        print(f"Webshell results written to TXT: result/{txt_output_file}")
    if json_output_file:
        write_json(final_results, os.path.join("result", json_output_file))
        print(f"Webshell results written to JSON: result/{json_output_file}")

    summary_file = os.path.join("logs", f"scan_summary_{timestamp}.json")
    time_end = time.time()
    summary = {
        "TotalFilesFound": total_files,
        "PotentialWebshells": len(webshell_paths),
        "TotalFilesIgnored": total_ignored,
        # "TotalFilesScanned": len(final_results),
        # "TotalFilesScannedPaths": all_paths,
        "UnreadableFile": len(all_unreadable_paths),
        "WebshellPaths": webshell_paths,
        "FilesIgnoredPath": all_ignored_paths,
        "UnreadableFilePath": all_unreadable_paths,
        "ScanTime": f"{time_end - time_start:.2f} seconds"
    }
    write_summary(summary, summary_file)
    print(f"Summary written to: {summary_file}")

    if webshell_paths:
        zip_webshell_files(webshell_paths)
    else:
        print("[+] No webshell files found for zipping.")
