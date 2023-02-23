#!/usr/bin/env python3

import sys
import subprocess
import os 
import random

# Unpacking with UPX...
filename = sys.argv[1]
print(filename)

rand_num = random.randint(1, 999)

# set path current working diretory
working_directory = os.getcwd()
# set path to upx_unpacker
upx_unpacker_path = os.path.join(working_directory, 'upx.exe')
print(upx_unpacker_path)
p = subprocess.Popen([upx_unpacker_path, '-d', '-o', str(rand_num) + 'realunpacked.exe', filename])

# Done unpacking with UPX

