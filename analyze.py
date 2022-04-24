#!/usr/bin/env python3

import os
from tkinter import *
from tkinter import filedialog

def browseFiles(label_file_explorer):
    filename = filedialog.askopenfilename(initialdir = "/",
                                          title = "Select a File",
                                          filetypes = (("Text files",
                                                        "*.txt*"),
                                                       ("all files",
                                                        "*.*")))
      
    # Change label contents
    label_file_explorer.configure(text="File Opened: "+filename)

    # Show button to extract imports

    # Show button to analyze imports

    

def main():
    root = Tk()
    root.geometry("700x500")
    root.title("File Analyzer")
    root.config(bg="#f7e4e4")

    label_file_explorer = Label(root,
                            text = "File Explorer using Tkinter",
                            width = 100, height = 4,
                            fg = "blue")
  
      
    button_explore = Button(root,
                            text = "Browse Files",
                            command = lambda: browseFiles(label_file_explorer))
    
    button_exit = Button(root,
                        text = "Exit",
                        command = exit)
    
    # Grid method is chosen for placing
    # the widgets at respective positions
    # in a table like structure by
    # specifying rows and columns
    label_file_explorer.grid(column = 1, row = 1)
    
    button_explore.grid(column = 1, row = 2)
    
    button_exit.grid(column = 1,row = 3)

    root.mainloop()

if __name__ == "__main__":
    main()