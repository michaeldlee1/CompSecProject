

# imports
import os
import sys
import pefile
import pprint

# globals
mode = ""

# functions
# returns a dict of {import: [filename of each file that imports that call], ... }
def parseDir(directory):
    imports = {}
    i = 0
    for filename in os.listdir(directory):
        path = directory + "/" + filename
        file_data = extractFile(path)
        i += 1  
        if not file_data:
            continue
        for imp in file_data:
            if imp not in imports:
                    imports[imp] = [filename]
            else:
                imports[imp].append(filename)
        if i >= 100:
            break
    return imports
        
# returns a list of the import table for this file 
def extractFile(file):
    imports = []
    try:
        pe = pefile.PE(file, fast_load=True)
    except Exception as e:
        print(e)
        return
    pe.parse_data_directories()
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for import_item in entry.imports:
            if import_item.name:
                imports.append(import_item.name.decode())
            #print(f'{import_item.name}: \t {hex(import_item.address)}')
    return imports
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
        file = sys.argv[2]
        mode = "FILE"
    else:
        print("Must specify a mode")
        exit(1)
    if mode == "DIR":
        data = parseDir(directory)
        for import_name in data.keys():
            print(f'{import_name}: {len(data[import_name])}')
    else:
        data = extractFile(file)

if __name__ == '__main__':
    main()