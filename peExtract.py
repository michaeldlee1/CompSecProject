#!/usr/bin/env python3

import os
import sys
import json
import pefile
from collections import defaultdict


def parse_dir(directory):
    """
    returns a dict of
      {
        file: [imports], ... 
      }
    """
    imports = dict()

    for i, filename in enumerate(os.listdir(directory)):
        path = os.path.join(directory, filename)
        file_imports = extract_file(path)

        if file_imports is None:
            continue

        imports[filename] = file_imports

    return imports


def parse_dir_2(directory):
    """
    returns a dict of
      {
        import: [files (filenames) that import that call], ... 
      }
    """
    dir_imports = defaultdict(list)

    for i, filename in enumerate(os.listdir(directory)):
        path = os.path.join(directory, filename)
        file_imports = extract_file(path)

        if file_imports is None:
            continue

        for imp in file_imports:
            dir_imports[imp].append(filename)

    return dir_imports
        

def extract_file(filename, sort_imports=True):
    """
    returns a list of the import table for this filename 
    """
    imports = []

    try:
        pe = pefile.PE(filename, fast_load=True)
    except Exception as e:
        print(f"Error parsing {filename}: {e}", file=sys.stderr)
        return None 

    pe.parse_data_directories()
    try:
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for import_item in entry.imports:
                if import_item.name:
                    imports.append(import_item.name.decode())
                #print(f'{import_item.name}: \t {hex(import_item.address)}')

        if sort_imports:
            imports.sort()
    except:
        pass
    return imports


def main():
    if len(sys.argv) < 3:
        # -d for whole directory or -f for just a file
        print("Usage: ./peExtract.py [-d Directory] [-f File]", file=sys.stderr)
        exit(1)

    # parse args
    dir_mode = False

    if sys.argv[1] == '-d': 
        directory = sys.argv[2] 
        dir_mode = True
    elif sys.argv[1] == '-f':
        filename = sys.argv[2]
    else:
        print("Must specify a mode", file=sys.stderr)
        sys.exit(1)

    if dir_mode:
        data = parse_dir(directory)
        print(json.dumps(data, indent=2))

    else:
        data = extract_file(filename)

        if data is None:
            print("Invalid PE file", file=sys.stderr)
            sys.exit(1)

        print(json.dumps(data, indent=2))


if __name__ == '__main__':
    main()

