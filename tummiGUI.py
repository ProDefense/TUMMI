#!/usr/bin/env python3

from tkinter import filedialog
import tkinter as tk
import os

from PIL import ImageTk, Image
from tkinter.filedialog import askopenfile

#must enter this command in cmd
# pip install Pillow
base = False
root = tk.Tk()

canvas = tk.Canvas(root, width=1000,height=400)
canvas.grid(columnspan=3,rowspan=3)

#logo
logo = Image.open('banner2.png')
resize_image = logo.resize((1000,300))
img = ImageTk.PhotoImage(resize_image)

logo_label = tk.Label(image=img)
logo_label.image = img
logo_label.grid(column=1,row=0)

# instructions
instructions = tk.Label(root, text="Select an executable on your computer to analyze", font="Raleway")
instructions.grid(columnspan=3,row=1)

def open_file():
    global success
    global base
    if base:
        success.grid_forget()

    browser_text.set("loading...")
    file = filedialog.askopenfile(parent=root,mode='rb',title="Choose a file", filetype=[("Exe file", "*.exe")])
    if file:
        file_name = os.path.basename(file.name)
        name = os.path.splitext(file_name)[0]
        pack = "UNPACKED"
        hash = "HASH"
        file2 = open(f'{pack}-{name}.exe', "x")
        file2 = open(f'{hash}-{name}.txt', "x")

        # Code for unpacking and writing to the file

        base = True
        success = tk.Label(root, text="Your unpacked file and hash data has been added to your directory", font="Raleway")
        success.grid(columnspan=5,row=3)
        browser_text.set("Browse")
        return


#browser button
browser_text = tk.StringVar()
browser_btn = tk.Button(root, textvariable=browser_text, command=lambda:open_file(),font="Raleway", bg="#20bebe", fg="white",height=2,width=15)
browser_btn.grid(column=1,row=2)
browser_text.set("Browse")
canvas = tk.Canvas(root, width=1000,height=200)
canvas.grid(columnspan=3)

root.mainloop()

