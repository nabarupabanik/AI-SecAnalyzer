
import os
import subprocess

def list_files(user_input):
    # Command injection vulnerability
    os.system(f"ls {user_input}")
    return True

def process_data(data):
    # Another command injection
    os.system(f"cat {data}")
    return True

def run_command(cmd):
    # Using shell=True is dangerous
    subprocess.run(cmd, shell=True)
    return True
