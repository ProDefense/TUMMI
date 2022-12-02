# TUMMI
Tool for Unpacking Most Malware Intelligently (TUMMI)

The motivation behind The TUMMI Project project is to build a set of multiple unpacking capabilities that can be used for malware analysis. The program will have the capacity to identify how an executable was packed and automatically unpack it. After the potentially malicious executable is unpacked, it should then display different data ranging from children processes, payloads, file type, hashes and unpacked configuration files.

To run the program download tummiGUI.py and banner2.png.

Next select an executable to be automatically unpacked and have hash values saved to a text document.
(currently only works for files packed with UPX)

tummi.py is currently the backed of the program. This program can Find the MD5 and SHA256 hash of the file in question (both packed and unpacked),
List file information found by running the “file” command on Linux, and List file size.

We are currently working on connecting the backend capabilites with the tummiGUI



