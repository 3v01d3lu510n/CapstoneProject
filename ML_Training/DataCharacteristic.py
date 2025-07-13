#!/usr/bin/env python3
import os
import sys
from tree_sitter import Language, Parser
import tree_sitter_php as tsphp
import csv

# From version 7.2 onwards, assert() is no longer considered dangerous,
# but we keep it here for compatibility with older codebases.

# Define your blacklist of dangerous functions
EXEC_FUNCS = {
    "eval", "assert",
    "system", "exec", "passthru", "shell_exec", 'popen', 'proc_open'
}

USER_INPUTS = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"}

# Load the pre-compiled PHP grammar from tree-sitter-php
capsule      = tsphp.language_php()       # returns a PyCapsule
PHP_LANGUAGE = Language(capsule)          # wrap into a Language object
parser       = Parser(PHP_LANGUAGE)

def get_executetable_characteristics_flag(code):
    tree = parser.parse(code)
    root = tree.root_node
    
    def find_exec_func_call(node):
        """
        Recursively traverse the AST to find dangerous function calls.
        """
        stack = [root]
        while stack:
            node = stack.pop()
            if node.type == 'function_call_expression':
                func_node = node.child_by_field_name('function')
                if func_node is not None:
                    func_name = code[func_node.start_byte:func_node.end_byte].decode('utf8', errors='replace')
                    if func_name in EXEC_FUNCS:
                        args_node = node.child_by_field_name('arguments')
                        if args_node:
                            for arg in args_node.children:
                                if contains_user_input(arg):
                                    return 1
            stack.extend(node.children)
        return 0
    
    """
    Check if the argument node contains user input.
    """
    
    def contains_user_input(arg_node):
        stack = [arg_node]
        while stack:
            node = stack.pop()
            if node.type == 'variable_name':
                var_name = code[node.start_byte:node.end_byte].decode('utf8', errors='replace')
                if var_name in USER_INPUTS:
                    return 1
            stack.extend(node.children)
        return 0
    
    result = find_exec_func_call(root)
    return result if result is not None else 0

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <directory> output_csv")
        sys.exit(1)
    dir_path = sys.argv[1]
    
    if not os.path.isdir(dir_path):
        print(f"Error: {dir_path} is not a valid directory.")
        sys.exit(1)
    
    csv_path = sys.argv[2]
    with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['filename', 'characteristics_flag']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for root, dirs, files in os.walk(dir_path):
            for fname in files:
                php_path = os.path.join(root, fname)
                php_path = os.path.normpath(php_path)
                if not os.path.isfile(php_path):
                    continue
                try:
                    code = open(php_path, 'rb').read()
                    
                    if not code.strip():
                        print(f"{php_path} is empty.")
                        os.remove(php_path)
                        print(f"Removed empty file: {fname}")
                        continue
                    flag = get_executetable_characteristics_flag(code)
                    writer.writerow({'filename': php_path, 'characteristics_flag': flag})
                except Exception as e:
                    print(f"Error reading {php_path}: {e}")
                    continue
            
if __name__ == "__main__":
    main()