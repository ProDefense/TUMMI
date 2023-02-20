#!/usr/bin/env python3

import sys
import subprocess


# Unpacking with UPX...
filename = sys.argv[1]

p = subprocess.Popen(['./unpackers/upx/upx.exe', '-d', filename])
# Done unpacking with UPX