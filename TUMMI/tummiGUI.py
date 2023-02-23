#!/usr/bin/env python3

import tkinter as tk
import os
import hashlib
import subprocess
import pefile

from tkinter import filedialog
from PIL import ImageTk, Image

# must enter this command in cmd
# pip install Pillow

# base is for colors base = false means colors are in hex
base = False
# storing the top level window 'Tk()' as root
root = tk.Tk()

# set the size of the GUI
canvas = tk.Canvas(root, width=1000, height=400)
canvas.grid(columnspan=3, rowspan=7)

# set the banner
logo = Image.open('banner2.png')
resize_image = logo.resize((1000, 300))
img = ImageTk.PhotoImage(resize_image)

logo_label = tk.Label(image=img)
logo_label.image = img
logo_label.grid(column=1, row=0)

# instruction text
instructions = tk.Label(root, text="Select an executable on your computer to analyze", font="Raleway")
instructions.grid(columnspan=3, row=1)

# set path current working diretory
working_directory = os.getcwd()
# set path to upx_unpacker
upx_unpacker_path = os.path.join(working_directory, 'upx_unpacker.py')

# function to find the filesize 
def filesize(fileobj):
    fileobj.seek(0, os.SEEK_END)  # read from beginning to end
    return fileobj.tell()

def change_permissions(selected):
    # Set the new permissions
    new_permissions = 0o777 

    # Change the permissions of the file
    os.chmod(selected, new_permissions)



def open_file():
    global success
    global base
    if base:
        success.grid_forget()

    browser_text.set("loading...")
    selected_file = filedialog.askopenfile(parent=root, mode='rb', title="Choose a file", filetype=[("Exe file", "*.exe")])
    
    if selected_file:
        file_name = os.path.basename(selected_file.name)
        file_path = os.path.abspath(selected_file.name)
        name = os.path.splitext(file_name)[0]
        pack_str = "UNPACKED"
        hash_str = "HASH"

        # Code for unpacking and writing to the file
        # Figure out which unpacker to call based on any signatures left in the file
        content = selected_file.read()
        packerFound = False
        packer = "Not Found"
        
        success = tk.Label(root, text="Your unpacked file and hash data has been added to your directory", font="Raleway")
        success.grid(columnspan=3, row=4)
        theHash = tk.Label(root, text=' ' , font="Raleway")
        theHash.grid(columnspan=3, row=5)
        theSize = tk.Label(root, text=' ', font="Raleway")
        theSize.grid(columnspan=3, row=6)
        success.configure(text="            ")
        theHash.configure(text="            ")
        theSize.configure(text="            ")
        #success = tk.Label(root, text="Sorry, we could not identify how this file was packed.", font="Raleway")
        #success.grid(columnspan=3, row=4)
        # 1. UPX:

        def is_upx_packed(file_path):
            try:
                pe = pefile.PE(file_path)
                for section in pe.sections:
                    if b'UPX' in section.Name:
                        return True
                return False
            except pefile.PEFotmatError:
                print("not a portable executable (pe) file type")

        # Done finding packer and running unpacker. Give unpacked file and hash data, unless no packer was identified.
        if is_upx_packed(file_path) == True:
            #file2 = open(f'{pack_str}-{name}.exe', "w")
            file3 = open(f'{hash_str}-{name}.txt', "w")
            
            subprocess.call(['python3',upx_unpacker_path, file_path])

            with open(selected_file.name, 'rb') as f:
                hashContents = hashlib.md5(f.read()).hexdigest()

            file3.write(hashContents)

            base = True
            success.configure(text="Your unpacked file and hash data has been added to your directory.")
            
            size_of_file = filesize(selected_file)
            
            theHash.configure(text='    File MD5 Hash: ' + hashContents + '    ' )
            
            theSize.configure(text='    File Size: ' + str(size_of_file) + ' bytes    ')
            browser_text.set("Browse")

            return
        else:
            base = True
            success.configure(text="Sorry, we could not identify how this file was packed.")

            theHash.configure(text='                                                                                             ')
            theSize.configure(text='                                                                ')
            browser_text.set("Browse")
            
            return
# browser button
#browser_text.set("Browse")
browser_text = tk.StringVar()
browser_btn = tk.Button(root, textvariable=browser_text, command=lambda: open_file(), font="Raleway", bg="#20bebe",
                        fg="white", height=2, width=15)
browser_btn.grid(column=1, row=2)
browser_text.set("Browse")
canvas = tk.Canvas(root, width=1000, height=200)
canvas.grid(columnspan=3)

root.grid_rowconfigure(1, minsize=70)
root.grid_rowconfigure(4, minsize=70)
root.grid_rowconfigure(5, minsize=70)
root.grid_rowconfigure(6, minsize=70)

root.mainloop()