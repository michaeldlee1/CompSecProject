#!/usr/bin/env python3

import os
from tkinter import *
from tkinter import filedialog
from run_model import test_model
from train import Model
from peExctFuncs import *


class Screen():
    def __init__(self):
        self.root = Tk()
        self.root.title("File Analyzer")
        self.root.geometry("700x500")
        self.root.resizable(width=False, height=False)

        self.createSelectFileWindow()
        self.createImportWindow()
        self.createFileListWindow()
        self.createResultWindow()
        
        self.modelName = StringVar()
        self.modelName.set("model-decision-tree.pkl")
        self.models = [
            "model-decision-tree.pkl",
            "model-random-forest.pkl",
            "model-svm.pkl",
            "model-naive-bayes.pkl",
            "model-adaboost.pkl",
        ]
        self.root.mainloop()


    def createSelectFileWindow(self):
        # Create a frame for the file explorer
        self.selectFrame = Frame(self.root)
        self.selectFrame.place(relwidth=0.5, relheight=0.5, relx=0.01, rely=0.51)

        # Create a label for the file explorer
        self.label_file_explorer = Label(self.selectFrame,
                                    text="Select a File to Analyze",
                                    width=100, height=4,
                                    fg="blue")

        # Create a button to browse for a file
        button_explore = Button(self.selectFrame,
                                text="Browse Files",
                                command=lambda: self.browseFiles())

        button_dir = Button(self.selectFrame,
                            text="Browse Directory",
                            command=lambda: self.browseDir())
        
        # Create a button to exit the program
        button_exit = Button(self.selectFrame,
                                text="Exit",
                                command=exit)

        # Pack the widgets
        self.label_file_explorer.pack()
        button_explore.pack()
        button_dir.pack()
        button_exit.pack()

    def createFileListWindow(self):
        self.fnameFrame = Frame(self.root)
        self.fnameFrame.place(relwidth=0.47, relheight=0.5, relx=0.01, rely=0.01)
        
        self.label_file_list = Label(self.fnameFrame,
                                    text="Select a File",
                                    width=100, height=2,
                                    fg="blue")
        self.label_file_list.pack()
        self.listFiles = Listbox(self.fnameFrame, width = int(700*.47), height = 20, font=("Courier", 12))
        self.listFiles.bind("<<ListboxSelect>>", self.clearImports)
        self.listFiles.pack(side="left", fill="y")
        self.scrollbar = Scrollbar(self.fnameFrame, orient="vertical")
        self.scrollbar.pack(side="right", fill="y")
        self.listFiles.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.listFiles.yview)


    def clearImports(self, event):
        try:
            self.button_analyze_imports.destroy()
            self.listImports.delete(0, END)
            self.label_result.destroy()
            self.label_file_explorer.configure(text="File Opened: " + self.listFiles.get(self.listFiles.curselection()))
        except:
            pass
        
    def createImportWindow(self):
        self.importFrame = Frame(self.root)
        self.importFrame.config(bg="#f73b3b")
        self.importFrame.place(relwidth=0.47, relheight=0.5, relx=0.52, rely=0.01)
        self.label_import_list = Label(self.importFrame,
                                    text="Imports",
                                    width=100, height=2,
                                    fg="blue")
        self.label_import_list.pack()
        self.listImports = Listbox(self.importFrame, width = int(700*.47), height = 20, font=("Courier", 12))
        self.listImports.pack(side="left", fill="y")
        self.scrollbar = Scrollbar(self.importFrame, orient="vertical")
        self.scrollbar.pack(side="right", fill="y")
        self.listImports.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.listImports.yview)

    def createResultWindow(self):
        self.resultFrame = Frame(self.root)
        self.resultFrame.place(relwidth=0.5, relheight=0.4, relx=0.51, rely=0.6)

    def browseFiles(self):
        filename = filedialog.askopenfilename(initialdir="/",
                                              title="Select a File",
                                              filetypes=(("Executables", "*.exe"),
                                                         ("all files", "*.*")))

        # Change label contents
        if filename != "":
            self.label_file_explorer.configure(text="File Opened: " + filename)
        else:
            self.label_file_explorer.configure(text="No File Selected")
            return

        self.showFiles([filename])

        # if buttons already exist, delete them
        try:
            self.button_extract_imports.destroy()
            for widget in self.resultFrame.winfo_children():
                widget.destroy()
            self.listImports.delete(0, END)
        except:
            pass

        # Show button to extract imports
        self.button_extract_imports = Button(self.resultFrame, text="Extract Imports",
                                        command=lambda: self.showImports(filename))
        self.button_extract_imports.pack()


    def browseDir(self):
        self.dirname = filedialog.askdirectory(initialdir="/",
                                          title="Select a Directory")

        #Open directory and display files
        self.showFiles(filter(lambda x: x.endswith(".exe"), os.listdir(self.dirname)))

        
        # Change label contents
        if self.dirname != "":
            self.label_file_explorer.configure(text="Directory Opened: " + self.dirname)
        else:
            self.label_file_explorer.configure(text="No Directory Selected")
            return

        # if buttons already exist, delete them
        try:
            self.button_extract_imports.destroy()
            for widget in self.resultFrame.winfo_children():
                widget.destroy()
            self.listImports.delete(0, END)
        except:
            pass

        # Show button to extract imports
        self.button_extract_imports = Button(self.resultFrame, text="Extract Imports",
                                        command=lambda: self.showImportsFromDir())
        self.button_extract_imports.pack()


    def showFiles(self, fileList):
        # Show file in listbox
        self.listFiles.delete(0, END)
        for file in fileList:
            self.listFiles.insert(END, file)

        self.root.update()

    def showImports(self, filename):
        imports = peExtract(filename)
        self.listImports.delete(0, END)
        for imp in imports:
            self.listImports.insert(END, imp)

        try:
            self.label_result.destroy()
            self.button_analyze_imports.destroy()
        except:
            pass
        
        self.selectModel = OptionMenu(self.resultFrame, self.modelName, *self.models)
        self.selectModel.pack()

        self.button_analyze_imports = Button(self.resultFrame, text="Analyze Imports",
                                        command=lambda: self.analyzeImports(filename))
        self.button_analyze_imports.pack()
        
        self.root.update()

    def showImportsFromDir(self):
        try: 
            filename = self.listFiles.get(self.listFiles.curselection())
            print(filename)
            # Get full filepath
            imports = peExtract(os.path.join(self.dirname, filename))
            self.listImports.delete(0, END)
            for imp in imports:
                self.listImports.insert(END, imp)
        except:
            self.label_file_explorer.configure(text="Invalid File")
        
        try:
            self.button_analyze_imports.destroy()
            self.label_result.destroy()
        except:
            pass

        self.button_analyze_imports = Button(self.resultFrame, text="Analyze Imports",
                                        command=lambda: self.analyzeImports(filename))
        self.button_analyze_imports.pack()

        self.root.update()

    def analyzeImports(self, filename):
        # Get current model selection from dropdown
        modelName = self.modelName.get()
        # Display result of running against model
        if modelName == "AdaBoost":
            model = model.load("model-adaboost.pkl")
        elif modelName == "Random Forest":
            model = model.load("model-random-forest.pkl")
        elif modelName == "Decision Tree":
            model = model.load("model-decision-tree.pkl")
        elif modelName == "Naive Bayes":
            model = model.load("model-naive-bayes.pkl")
        elif modelName == "SVC":
            model = model.load("model-svc.pkl")

        try:
            filename = os.path.join(self.dirname, filename)
            self.label_result.destroy()
        except:
            pass

        self.label_result = Label(self.resultFrame,
                                    text="Result",
                                    width=100, height=5,
                                    font=("Courier", 16),
                                    fg="white")

        if test_model(filename, model):
            self.label_result.configure(text="File is malicious", bg="red")
        else:
            self.label_result.configure(text="File is not malicious", bg="green")

        self.label_result.pack()