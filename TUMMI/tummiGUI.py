#!/usr/bin/env python3

import tkinter as tk
import os
import hashlib
import subprocess
import pefile

import sys
import yara

from tkinter import filedialog
from PIL import ImageTk, Image

# must enter this command in cmd
# pip install Pillow

# base is for colors base = false means colors are in hex
base = False
# storing the top level window 'Tk()' as root
root = tk.Tk()

# set the size of the GUI
canvas = tk.Canvas(root, width=1000, height=320)
canvas.grid(columnspan=3, rowspan=8)

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
        success.grid(columnspan=3, row=3)
        theHash = tk.Label(root, text=' ' , font="Raleway")
        theHash.grid(columnspan=3, row=6)
        theSize = tk.Label(root, text=' ', font="Raleway")
        theSize.grid(columnspan=3, row=7)
        theName = tk.Label(root, text=' ', font="Raleway")
        theName.grid(columnspan=3, row=5)
       
        success.configure(text="            ")
        theHash.configure(text="            ")
        theSize.configure(text="            ")
        theName.configure(text="            ")
        
        packerType = tk.Label(root, text=' ', font="Raleway")
        packerType.grid(columnspan=3, row=4)
        packerType.configure(text="            ")
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

        #determine which packer was used
        def which_packer(file_path):
            #yara rules
            source =  '''
            rule upx{
                strings:
                    $mz = "MZ"
                    $upx = "upX" wide ascii
                    $upx0 = "UPX0" wide ascii
                    $upx1 = "UPX1" wide ascii
                    $upx2 = "UPX2" wide ascii
                    $upxx = "UPX!" wide ascii
                condition:
                    $mz at 0 and ((2 of ($upx0, $upx1, $upx2)) or $upxx or $upx)
            }
            rule pecompact{
                strings:
                    $mz = "MZ"
                    $pec1 = "PE"
                    $pec2 = "PEC2"
                    $pec = "PECompact2"
                condition:
                    $mz at 0 and (($pec1 and $pec2) or $pec)
            }
            rule aspack{
                strings:
                    $mz = "MZ"
                    $asp = ".aspack"
                    $asp1 = ".adata"
                condition:
                    $mz at 0 and ($asp or $asp1)
            }
            rule mpress{
                strings:
                    $mz = "MZ"
                    $mp1 = ".MPRESS1"
                    $mp2 = ".MPRESS2"
                condition:
                    $mz at 0 and ($mp1 or $mp2)
            }
            rule mew{
                strings:
                    $mz = "MZ"
                    $mew1 = "MEW"
                condition:
                    $mz at 0 and $mew1
            }
            rule petite{
                strings:
                    $mz = "MZ"
                    $pet1 = ".petite"
                    $pet2 = "petite"
                condition:
                    $mz at 0 and ($pet1 or $pet2)
            }'''

            rules = yara.compile(source=source)
            matches = rules.match(file_path)
            if "upx" in str(matches):
                return "upx"
            elif "pecompact" in str(matches):
                return "pecompact"
            elif "aspack" in str(matches):
                return "aspack"
            elif "mpress" in str(matches):
                return "mpress"
            elif "mew" in str(matches):
                return "mew"
            elif "petite" in str(matches):
                return "petite"
            else:
                return "could not find packer"

        # Done finding packer and running unpacker. Give unpacked file and hash data, unless no packer was identified.
        if which_packer(file_path) == "upx":
            #file2 = open(f'{pack_str}-{name}.exe', "w")
            file3 = open(f'{hash_str}-{name}.txt', "w")
            
            if is_upx_packed(file_path) == True:
                a =1
            else:
                base = True
                success.configure(text="                   This file has already been unpacked by UPX                   ")
                theHash.configure(text='                                                                                             ')
                theSize.configure(text='                                                                ')
                theName.configure(text='                                                                                                                            ')
                packerType.configure(text="                                                                                                                     ")
                browser_text.set("Browse")
            
                return
            
            
            
            subprocess.call(['python3',upx_unpacker_path, file_path])

            with open(selected_file.name, 'rb') as f:
                hashContents = hashlib.md5(f.read()).hexdigest()

            file3.write(hashContents)

            base = True
            success.configure(text="Your unpacked file and hash data has been added to your directory.")
            
            size_of_file = filesize(selected_file)
            
            packerType.configure(text="     Your file was packed with: UPX     ")
            theName.configure(text='                Selected File : ' + selected_file.name + '                ' )
            theHash.configure(text='    File MD5 Hash: ' + hashContents + '    ' )
            
            theSize.configure(text='    File Size: ' + str(size_of_file) + ' bytes    ')
            browser_text.set("Browse")

            return
        
        #temporary placeholders before more unpacker implementations
        elif which_packer(file_path) == "pecompact":
            success.configure(text="        Sorry, automatic unpacker for PECompact is still under construction.        ")
            packerType.configure(text="   Your file was packed with: PECompact   ")
            theHash.configure(text='                                                                                             ')
            theSize.configure(text='                                                                ')
            browser_text.set("Browse")
            return
        
        elif which_packer(file_path) == "aspack":
            success.configure(text="        Sorry, automatic unpacker for PECompact is still under construction.        ")
            packerType.configure(text="   Your file was packed with: ASPack   ")
            theHash.configure(text='                                                                                             ')
            theSize.configure(text='                                                                ')
            browser_text.set("Browse")
            return
        
        elif which_packer(file_path) == "mpress":
            success.configure(text="        Sorry, automatic unpacker for PECompact is still under construction.        ")
            packerType.configure(text="   Your file was packed with: MPRESS   ")
            theHash.configure(text='                                                                                             ')
            theSize.configure(text='                                                                ')
            browser_text.set("Browse")
            return
        
        elif which_packer(file_path) == "mew":
        
            with open(selected_file.name, 'rb') as f:
                hashContents = hashlib.md5(f.read()).hexdigest()
            size_of_file = filesize(selected_file)
            
            theName.configure(text='                Selected File : ' + selected_file.name + '                ' )
            theSize.configure(text='    File Size: ' + str(size_of_file) + ' bytes    ')
            theHash.configure(text='    File MD5 Hash: ' + hashContents + '    ' )
            success.configure(text="        Sorry, automatic unpacker for MEW is still under construction.        ")
            packerType.configure(text="   Your file was packed with: MEW   ")
            #theHash.configure(text='                                                                                             ')
            #theSize.configure(text='                                                                ')
            browser_text.set("Browse")
            return
        
        elif which_packer(file_path) == "petite":
            with open(selected_file.name, 'rb') as f:
                hashContents = hashlib.md5(f.read()).hexdigest()
            size_of_file = filesize(selected_file)
            
            theName.configure(text='                Selected File : ' + selected_file.name + '                ' )
            theSize.configure(text='    File Size: ' + str(size_of_file) + ' bytes    ')
            theHash.configure(text='    File MD5 Hash: ' + hashContents + '    ' )
            success.configure(text="        Sorry, automatic unpacker for PEtite is still under construction.        ")
            packerType.configure(text="   Your file was packed with: PEtite   ")
            #theHash.configure(text='                                                                                             ')
            #theSize.configure(text='                                                                ')
            browser_text.set("Browse")
            return
        
        else:
            base = True
            success.configure(text="          Sorry, we could not identify how this file was packed.          ")
            theName.configure(text='                                                                                                                                             ')
            theHash.configure(text='                                                                                             ')
            theSize.configure(text='                                                                ')
            browser_text.set("Browse")
            packerType.configure(text="                                                                               ")
            
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
root.grid_rowconfigure(3, minsize=70)
root.grid_rowconfigure(4, minsize=70)
root.grid_rowconfigure(5, minsize=70)
root.grid_rowconfigure(6, minsize=70)
root.grid_rowconfigure(7, minsize=70)

root.mainloop()