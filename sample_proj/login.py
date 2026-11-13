import hashlib
import os
import subprocess

user_input = input()
query = "SELECT * FROM users WHERE name = " + user_input
print(query)

h = hashlib.md5(user_input.encode())

open(user_input, "w").write("x")

password = "supersecret"

os.system(user_input)
subprocess.run(user_input, shell=True)

