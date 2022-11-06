import tkinter as tk

from PIL import ImageTk, Image
from tkinter.filedialog import askopenfile

#must enter this command in cmd
# pip install Pillow

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
    browser_text.set("loading...")
    file = askopenfile(parent=root,mode='rb',title="Choose a file", filetype=[("Exe file", "*.exe")])
    if file:
        print("file was successfully loaded")


#browser button
browser_text = tk.StringVar()
browser_btn = tk.Button(root, textvariable=browser_text, command=lambda:open_file(),font="Raleway", bg="#20bebe", fg="white",height=2,width=15)
browser_text.set("Browse")
browser_btn.grid(column=1,row=2)

canvas = tk.Canvas(root, width=1000,height=200)
canvas.grid(columnspan=3)

root.mainloop()

