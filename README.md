# TUMMI
## Tool for Unpacking Most Malware Intelligently

The motivation behind The TUMMI Project project is to build a set of multiple unpacking capabilities that can be used for malware analysis. The program will have the capacity to identify how an executable was packed and automatically unpack it. After the potentially malicious file is unpacked, it should then display different data ranging from children processes, payloads, file type, hashes and unpacked configuration files.

## Installation:

To install the TUMMI Software, simply run
```git clone https://github.com/ProDefense/TUMMI/
cd TUMMI
pip3 install -r requirements.txt
```

## Running the Program:

Once inside the TUMMI folder, there are two ways to execute TUMMI. For most users, one can simply run

```python3 tummiGUI.py```

This can be shorted by running `chmod +x tummiGUI.py` on the file. From there, simply typing

```./tummiGUI.py```

should work. On windows, typing `.\tummiGUI.py` is equivalent.

Next, select whichever executable to be automatically unpacked and have hash values saved to a text document in the same folder.
*Note:* this currently only works for files packed with UPX, we are in the process of expanding this list!

`tummi.py` is the backed of the program. This program can:
- Find the MD5 and SHA256 hash of the file in question (both packed and unpacked),
- List file information found by running the “file” command on Linux, and
- List file size.

We are currently working on connecting the backend capabilites with the tummiGUI to create a much richer user experience.

If you have any questions, comments, or concerns, please feel free to reach out to us!
