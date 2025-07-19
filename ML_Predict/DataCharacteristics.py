import os
import sys
from tree_sitter import Language, Parser
import tree_sitter_php as tsphp

class ASTAnalyzer:
    # Define dangerous functions
    EXEC_FUNCS = {
        "eval", "assert",
        "system", "exec", "passthru", "shell_exec", 'popen', 'proc_open'
    }
    
    USER_INPUTS = {"$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_FILES"}
    
    # Load the pre-compiled PHP grammar from tree-sitter-php
    capsule      = tsphp.language_php()       
    PHP_LANGUAGE = Language(capsule)          
    parser       = Parser(PHP_LANGUAGE)
    code = None
    
    def __init__(self):
        pass
    
    def get_executetable_characteristics_flag(self, code):

        tree = self.parser.parse(code)
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
                        if func_name in self.EXEC_FUNCS:
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
                    if var_name in self.USER_INPUTS:
                        return 1
                stack.extend(node.children)
            return 0
        
        result = find_exec_func_call(root)
        return result if result is not None else 0
    
    def evaluate_file_characteristics(self, file_bytes):
        try:
            code = file_bytes.read()
            if not code.strip():
                return None
            return self.get_executetable_characteristics_flag(code)
        except Exception as e:
            return None

