import os
import sys
import hashlib
import subprocess

def filesize(fileobj):
    fileobj.seek(0, os.SEEK_END)    # read from beginning to end
    return fileobj.tell()           # returns number of bytes read

def fileread(filename, encoding='utf-8'):
    read = 'r'
    if encoding == 'utf-8':
        encoding = None
        read = 'rb'
    with open(filename, read, encoding=encoding) as fileobj:
        fileobj.seek(0)             # go to beginning of file
        content = fileobj.read()
        if encoding:
            return content.decode(encoding).rstrip('\n')
        else:
            return content.decode('utf-8').rstrip('\n')

def filetype(filename):
    file_attr = subprocess.Popen(["file", filename], stdout = subprocess.PIPE)
    return file_attr.stdout.readline().decode('utf-8').lstrip(filename + ": ")

def filehashes(filename, encoding='utf-8', block_size=1024):
    read = 'r'
    if encoding == 'utf-8':
        encoding = None
        read = 'rb'
    with open(filename, read, encoding=encoding) as fileobj:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        fileobj.seek(0)                 # go to beginning of file
        while True:                     # read specified length
            data = fileobj.read(block_size)
            if not data:
                break                   # file contains nothing else, quit
            md5.update(data)
            sha256.update(data)
        return (md5.hexdigest(), sha256.hexdigest())  # return both hashes as a tuple

if __name__ == '__main__':
    file_to_analyze = sys.argv[1]
    f = open(file_to_analyze, 'r')

    size_of_file = filesize(f)
    print(f"File size: {size_of_file} bytes")

    type_of_file = filetype(file_to_analyze)
    print(f"File information: {type_of_file}")

    try:
        md5, sha256 = filehashes(file_to_analyze)

        print(f"MD5: {md5}")
        print(f"SHA256: {sha256}\n")
    except:
        print("Unrecognized file format, please let us know so we can figure out a solution in the future!")

    try:
        file_content = fileread(file_to_analyze)
        print("Content of file:")
        print(file_content)
    except:
        print("Unrecognized file format, please let us know so we can figure out a solution in the future!")
