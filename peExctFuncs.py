#!/usr/bin/env python3

import os
import sys
import pefile
import pprint
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
        imports[filename] = extract_file(path)

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

        if not file_imports:
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
        #print(e, file=sys.stderr)
        return None 

    pe.parse_data_directories()
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for import_item in entry.imports:
            if import_item.name:
                imports.append(import_item.name.decode())
            #print(f'{import_item.name}: \t {hex(import_item.address)}')

    if sort_imports:
        imports.sort()

    return imports


def peExtract(filename):
    

    data = extract_file(filename)

    if data is None:
        print("Invalid PE file", file=sys.stderr)
        return

    for api_call in data:
        print(api_call)

    return data

