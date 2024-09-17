#!/opt/pwn.college/python

import subprocess
import traceback
import pwd
import sys
import os

def demote_user(user_uid, user_gid):
    """ method to demote the user env to the 'hacker' user to avoid /flag read attempts """
    def result():
        os.setgid(user_gid)
        os.setuid(user_uid)
    return result

def get_variables(script_path):
    """ Get a dict of defined variables and their types from the students script """
    import importlib

    module_name = script_path.replace('.py','')
    module = importlib.import_module(module_name)

    vars = {}
    module_dict = module.__dict__
    for name, value in module_dict.items():
        # Skip built-in attributes
        if name.startswith('__'):
            continue

        value_type = type(value).__name__
        vars[name] = {value_type: value}

    return vars

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
