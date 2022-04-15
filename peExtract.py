#!/usr/bin/env python3

# imports
import os
import sys
import pefile

# globals
mode = ""

# functions
def parseDir(directory):
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        extractFile(path)

def extractFile(file):
    pe = pefile.PE(file, fast_load=True)
    pe.parse_data_directories()
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(entry.dll)
            for import_item in entry.imports:
                print(f'{import_item.name}: \t {hex(import_item.address)}')
    except AttributeError:
        print(f'Attribute Error on: {file}')

# main
def main():
    # parse argv
    if len(sys.argv) < 3:
        print("Usage: ./peExtract.py -d Directory -f File") # can do -d to do whole directory or -f for just a file
        exit(1)
    if sys.argv[1] == '-d': 
        # directory mode
        directory = sys.argv[2]
        mode = "DIR"
    elif sys.argv[1] == '-f':
        field = sys.argv[2]
        mode = "FILE"
    else:
        print("Must specify a mode")
        exit(1)
    if mode == "DIR":
        parseDir(directory)
    else:
        extractFile(file)

if __name__ == '__main__':
    main()