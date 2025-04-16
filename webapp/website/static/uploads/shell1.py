#!/usr/bin/python3

import os

print("Content-Type: text/plain\n")  # Necessary for CGI execution
print("Reading /etc/passwd...\n")

# Execute command and print output
output = os.popen("cat /etc/passwd").read()
print(output)
