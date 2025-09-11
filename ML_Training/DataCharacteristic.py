#!/usr/bin/env python3
import os
import sys
from tree_sitter import Language, Parser
import tree_sitter_php as tsphp
import csv
import codecs
import base64

# Define your blacklist of dangerous functions
EXEC_FUNCS = {
    "eval", "assert",
    "system", "exec", "passthru", "shell_exec", 'popen', 'proc_open'
}

OBFU_FUNCS = {"base64_decode", "str_rot13"}

USER_INPUTS = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"}

# Load the pre-compiled PHP grammar from tree-sitter-php
capsule      = tsphp.language_php()       # returns a PyCapsule
PHP_LANGUAGE = Language(capsule)          # wrap into a Language object
parser       = Parser(PHP_LANGUAGE)

def get_function_argument(args_node, code):
    """Extract single argument from arguments node."""
    if args_node.type == 'arguments' and args_node.named_children:
        arg_node = args_node.named_children[0]
        arg_text = code[arg_node.start_byte:arg_node.end_byte].decode('utf8', errors='replace')
        return arg_text.strip('"\'')
    return None

def find_obfu_func_calls(node, code):
    """Recursively traverse the AST to find and decode obfuscated function calls."""
    dangerous_calls = []
    stack = [node]
    
    while stack:
        current_node = stack.pop()
        if current_node.type == 'function_call_expression':
            func_node = current_node.child_by_field_name('function')
            if func_node:
                func_name = code[func_node.start_byte:func_node.end_byte].decode('utf8', errors='replace')
                if func_name in OBFU_FUNCS:
                    args_node = current_node.child_by_field_name('arguments')
                    if args_node:
                        arg_value = get_function_argument(args_node, code)
                        if arg_value:
                            call_info = {
                                'function': func_name,
                                'argument': arg_value,
                                'line': current_node.start_point[0] + 1
                            }
                            
                            try:
                                if func_name == "base64_decode":
                                    # Add padding if needed
                                    padding_needed = len(arg_value) % 4
                                    if padding_needed:
                                        arg_value += '=' * (4 - padding_needed)
                                    decoded = base64.b64decode(arg_value).decode('utf-8', errors='replace')
                                elif func_name == "str_rot13":
                                    decoded = codecs.decode(arg_value, 'rot_13')
                                
                                call_info['decoded'] = decoded
                                dangerous_calls.append(call_info)
                                
                                try:
                                    decoded_code = bytes(f"<?php\n{decoded}\n?>", 'utf-8')
                                    decoded_tree = parser.parse(decoded_code)
                                    nested_calls = find_obfu_func_calls(decoded_tree.root_node, decoded_code)
                                    if nested_calls:
                                        call_info['nested_calls'] = nested_calls
                                except Exception:
                                    pass
                            except Exception as e:
                                continue
        
        stack.extend(current_node.children)
    
    return dangerous_calls

def get_deepest_call(call_info):
    """Get the deepest nested call from the call hierarchy."""
    current = call_info
    while 'nested_calls' in current and current['nested_calls']:
        current = current['nested_calls'][-1]
    return current

def get_executetable_characteristics_flag(code):
    """Check if the AST contains dangerous function calls with user input."""
    tree = parser.parse(code)
    root = tree.root_node
    
    # First check for obfuscated functions
    dangerous_calls = find_obfu_func_calls(root, code)
    if dangerous_calls:
        for call in dangerous_calls:
            final_call = get_deepest_call(call)
            final_code = bytes(f"<?php\n{final_call['decoded']}\n?>", 'utf-8')
            final_tree = parser.parse(final_code)
            if find_exec_func_call(final_tree.root_node, final_code):
                return 1
    
    # Then check for direct dangerous function calls
    return find_exec_func_call(root, code)

def find_exec_func_call(node, code):
    """Recursively traverse the AST to find dangerous function calls."""
    stack = [node]
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
                            if contains_user_input(arg, code):
                                return 1
        stack.extend(node.children)
    return 0

def contains_user_input(arg_node, code):
    """Check if the argument node contains user input."""
    stack = [arg_node]
    while stack:
        node = stack.pop()
        if node.type == 'variable_name':
            var_name = code[node.start_byte:node.end_byte].decode('utf8', errors='replace')
            if var_name in USER_INPUTS:
                return 1
        stack.extend(node.children)
    return 0

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
                # Get the absolute path of fname
                php_path = os.path.abspath(os.path.join(root, fname))
                
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