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
    
    def get_executetable_characteristics_flag(self, code_bytes):
        tree = self.parser.parse(code_bytes)
        root = tree.root_node
        
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

        stack = [root]
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

    def evaluate_file_characteristics(self, code_bytes):
        try:
            if not code_bytes.strip():
                return None
            return self.get_executetable_characteristics_flag(code_bytes)
        except Exception:
            return None
    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python ast_analyzer.py <dir_path>")
        sys.exit(1)

    dir_path = sys.argv[1]
    count = 0
    if os.path.isdir(dir_path):
        for root, _, files in os.walk(dir_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path.endswith('.php'):
                    with open(file_path, 'rb') as f:
                        code = f.read()
                    analyzer = ASTAnalyzer()
                    flag = analyzer.evaluate_file_characteristics(code)
                    if flag == 1:
                        count += 1
        print(f"Total files with dangerous functions: {count}")