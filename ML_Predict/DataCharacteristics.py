import os
import sys
from tree_sitter import Language, Parser
import tree_sitter_php as tsphp
import codecs, base64

class ASTAnalyzer:
    # Define dangerous functions
    EXEC_FUNCS = {
        "eval", "assert",
        "system", "exec", "passthru", "shell_exec", 'popen', 'proc_open'
    }
    
    USER_INPUTS = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"}
    
    OBFU_FUNCS = {"base64_decode", "str_rot13"}
    
    # Load the pre-compiled PHP grammar from tree-sitter-php
    capsule      = tsphp.language_php()       
    PHP_LANGUAGE = Language(capsule)          
    parser       = Parser(PHP_LANGUAGE)
    code = None
    
    def get_function_argument(self, args_node, code):
        """Extract single argument from arguments node."""
        if args_node.type == 'arguments' and args_node.named_children:
            arg_node = args_node.named_children[0]
            arg_text = code[arg_node.start_byte:arg_node.end_byte].decode('utf8', errors='replace')
            return arg_text.strip('"\'')
        return None    
    
    def find_obfu_func_calls(self, node, code):
        """Recursively traverse the AST to find and decode obfuscated function calls."""
        dangerous_calls = []
        stack = [node]
    
        while stack:
            current_node = stack.pop()
            if current_node.type == 'function_call_expression':
                func_node = current_node.child_by_field_name('function')
                if func_node:
                    func_name = code[func_node.start_byte:func_node.end_byte].decode('utf8', errors='replace')
                    if func_name in self.OBFU_FUNCS:
                        args_node = current_node.child_by_field_name('arguments')
                        if args_node:
                            arg_value = self.get_function_argument(args_node, code)
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
                                        decoded_tree = self.parser.parse(decoded_code)
                                        nested_calls = self.find_obfu_func_calls(decoded_tree.root_node, decoded_code)
                                        if nested_calls:
                                            call_info['nested_calls'] = nested_calls
                                    except Exception:
                                        # If we can't parse the decoded value as PHP, just continue
                                        pass
                                except Exception as e:
                                    # If decoding fails, skip this function call
                                    continue
            
            stack.extend(current_node.children)
        
        return dangerous_calls

    def get_deepest_call(self, call_info):
        """Get the deepest nested call from the call hierarchy."""
        current = call_info
        while 'nested_calls' in current and current['nested_calls']:
            current = current['nested_calls'][-1]
        return current
    
    
    def __init__(self):
        pass
    
    def find_exec_func_call(self, node, code_bytes):

        def contains_user_input(arg_node):
            stack = [arg_node]
            while stack:
                node = stack.pop()
                if node.type == 'variable_name':
                    var_name = code_bytes[node.start_byte:node.end_byte].decode('utf8', errors='replace')
                    if var_name in self.USER_INPUTS:
                        return True
                stack.extend(node.children)
            return False

        stack = [node]
        while stack:
            node = stack.pop()
            if node.type == 'function_call_expression':
                func_node = node.child_by_field_name('function')
                if func_node is not None:
                    func_name = code_bytes[func_node.start_byte:func_node.end_byte].decode('utf8', errors='replace')
                    if func_name in self.EXEC_FUNCS:
                        args_node = node.child_by_field_name('arguments')
                        if args_node:
                            for arg in args_node.children:
                                if contains_user_input(arg):
                                    return 1
            stack.extend(node.children)
        return 0

    def get_executetable_characteristics_flag(self, code):
        """Check if the AST contains dangerous function calls with user input."""
        try:
            # Handle different input types
            if isinstance(code, str):
                # If input is a file path, read the file
                if os.path.isfile(code):
                    with open(code, 'rb') as f:
                        code_bytes = f.read()
                else:
                    code_bytes = code.encode('utf-8')
            else:
                # Already in bytes format
                code_bytes = code
                
            tree = self.parser.parse(code_bytes)
            root = tree.root_node
            
            # First check for obfuscated functions
            dangerous_calls = self.find_obfu_func_calls(root, code_bytes)
            if dangerous_calls:
                for call in dangerous_calls:
                    final_call = self.get_deepest_call(call)
                    final_code = bytes(f"<?php\n{final_call['decoded']}\n?>", 'utf-8')
                    final_tree = self.parser.parse(final_code)
                    if self.find_exec_func_call(final_tree.root_node, final_code):
                        return 1
            
            # Then check for direct dangerous function calls
            return self.find_exec_func_call(root, code_bytes)
        except Exception as e:
            print(f"Error analyzing code: {str(e)}")
            return 0
    