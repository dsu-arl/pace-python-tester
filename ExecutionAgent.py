#!/opt/pwn.college/python

import subprocess
import importlib
import traceback
import ast
import pwd
import sys
import os
import re

def demote_user(user_uid, user_gid):
    """ method to demote the user env to the 'hacker' user to avoid /flag read attempts """
    def result():
        os.setgid(user_gid)
        os.setuid(user_uid)
    return result

def get_defined_variables(script_path):
    """
    Parses the user's Python script and returns a dictionary of defined variables
    and functions, along with their inferred types and initial values.
    This method does not execute the code, making it safer.

    EXAMPLE
    {'variables': {'a': {'type': 'Str', 'initial_value': 'hello'}, 'b': {'type': 'Int', 'initial_value': 1}}, 'functions': {'hello'}}
    """

    if not script_path.endswith('.py'):
        raise ValueError("Your script must end with '.py'")

    # Read the script file
    with open(script_path, 'r') as file:
        code = file.read()

    # Parse the code into an Abstract Syntax Tree (AST)
    tree = ast.parse(code)

    defined_names = {
        'variables': {},
        'functions': set(),
    }

    class NameCollector(ast.NodeVisitor):
        def visit_Assign(self, node):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    # Get the value being assigned
                    value = node.value
                    inferred_type = type(value)
                    # Attempt to extract a representative value if possible
                    initial_value = self.get_initial_value(value)
                    defined_names['variables'][target.id] = {
                        'type': self.get_type_name(inferred_type, initial_value),
                        'initial_value': initial_value
                    }
            self.generic_visit(node)

        def visit_FunctionDef(self, node):
            defined_names['functions'].add(node.name)
            self.generic_visit(node)

        def get_initial_value(self, value):
            # Check for different types using ast.Constant
            if isinstance(value, ast.Constant):
                return value.value  # Directly return the constant value
            elif isinstance(value, ast.List):
                return [self.get_initial_value(el) for el in value.elts]
            elif isinstance(value, ast.Dict):
                return {self.get_initial_value(k): self.get_initial_value(v) for k, v in zip(value.keys, value.values())}
            elif isinstance(value, ast.Name):
                return value.id  # Returning the name itself
            return None  # For unsupported types

        def get_type_name(self, inferred_type, initial_value):
            # Map inferred types to desired output type names
            if isinstance(initial_value, str):
                return 'Str'
            elif isinstance(initial_value, int):
                return 'Int'
            elif isinstance(initial_value, float):
                return 'Float'
            elif isinstance(initial_value, list):
                return 'List'
            elif isinstance(initial_value, dict):
                return 'Dict'
            return 'Unknown'  # For unsupported types

    # Collect variable and function names
    NameCollector().visit(tree)

    return defined_names

def parse_script(script_path, regex):
    """ Checks a users script for specified regex match """

    if not script_path.endswith('.py'):
        raise ValueError("Your script must end with '.py'")

    regex = re.compile(regex)
    with open(script_path, 'r') as script:
        content = script.read()

        if not regex.search(content):
            return False

        return True

def run(script_path, input=""):
    try:
        # Get user info to demote and avoid /flag read attempts
        username = "hacker"
        pw_record = pwd.getpwnam(username)
        user_uid = pw_record.pw_uid
        user_gid = pw_record.pw_gid

        # Run the user's script using subprocess
        p = subprocess.Popen(
            ["python", script_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=demote_user(user_uid, user_gid),
            text=True
        )

        stdout, stderr = p.communicate(input=input)
        return stdout, stderr

    except Exception as e:
        print("Unexpected error occurred:")
        traceback.print_exc()
