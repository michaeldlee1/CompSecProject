#!/usr/bin/env python3

from Screen import *

def showImports(root, importFrame, filename):
    imports = peExtract(filename)
    listbox = Listbox(importFrame, width = 20, height = 20)
    listbox.pack(side="left", fill="y")
    scrollbar = Scrollbar(importFrame, orient='vertical')
    listbox.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=listbox.yview)
    scrollbar.pack(side="right", fill="y")
    for imp in imports:
        listbox.insert(END, imp)

    
    root.update()


def browseFiles(root, selectFrame, label_file_explorer):
    filename = filedialog.askopenfilename(initialdir = "/",
                                          title = "Select a File",
                                          filetypes = (("Executables", "*.exe"),
                                                       ("all files", "*.*")))
      
    # Change label contents
    label_file_explorer.configure(text="File Opened: "+filename)

    # Show button to extract imports
    button_extract_imports = Button(selectFrame, text="Extract Imports",
                                    command=lambda: showImports(root, filename))
    button_extract_imports.pack()
    # Run Mike stuff on filename

    # Show button to analyze imports against model

    # Put in Jack code here

    # Display result of running against model

def createSelectFileWindow(root):
    selectFrame = Frame(root)
    selectFrame.place(relwidth=0.6, relheight=0.5, relx=0.01, rely=0.01)

    label_file_explorer = Label(selectFrame,
                            text = "Select a File to Analyze",
                            width = 100, height = 4,
                            fg = "blue")
  
      
    button_explore = Button(root,
                            text = "Browse Files",
                            command = lambda: browseFiles(root, selectFrame, label_file_explorer))
    
    button_exit = Button(root,
                        text = "Exit",
                        command = exit)

    label_file_explorer.pack()
    button_explore.pack()
    button_exit.pack()

def createImportListWindow(root):
    importFrame = Frame(root)
    importFrame.config(bg="#f73b3b")
    importFrame.place(relwidth=0.37, relheight=0.5, relx=0.62, rely=0.01)

    listImports = Listbox(importFrame, width = 20, height = 20, font=("Courier", 12))
    listImports.pack(side="left", fill="y")
    scrollbar = Scrollbar(importFrame, orient="vertical")
    scrollbar.pack(side="right", fill="y")
    listImports.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=listImports.yview)


def main():
    screen = Screen()

if __name__ == "__main__":
    main()