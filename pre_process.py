#!/usr/bin/env python3

import os
import sys
import json
from collections import Counter
from vocab import Vocab, save_vocab


def parse_imports_dict(filename):
    with open(filename, 'r') as stream:
        imports = json.load(stream)
    return imports


def create_vocab(imports_dict):
    """
    create vocab with all imports used more than once
    """
    c = Counter()
    for import_list in imports_dict.values():
        c.update(import_list)
    
    v = Vocab()
    for word, count in c.items():
        if count > 1:
            v.add(word)

    return v


def make_import_vectors(imports_dict, vocab):
    """
    returns dict of filename -> one hot vectors
    """
    # returns dict of filename
    imports_dict_pre = dict()
    for filename, imports in imports_dict.items():
        imports_dict_pre[filename] = make_import_vector(imports, vocab)
    return imports_dict_pre


def make_import_vector(imports_list, vocab):
    """
    vec[i] represents number of occurances of i'th import
    """
    vec = [0] * len(vocab)
    for imp in imports_list:
        vec[vocab.numberize(imp)] += 1
    return vec


def save_preprocessed_imports(imports, stream):
    print(json.dumps(imports), file=stream)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} IMPORT_LIST", file=sys.stderr)
        sys.exit(1)

    import_list_file = sys.argv[1]

    imports_dict = parse_imports_dict(import_list_file)
    vocab = create_vocab(imports_dict)
    imports_dict = make_import_vectors(imports_dict, vocab)

    with open(import_list_file + ".pre", 'w') as stream:
        save_preprocessed_imports(imports_dict, stream)

    with open(import_list_file + ".vocab", 'w') as stream:
        save_vocab(vocab, stream)


if __name__ == "__main__":
    main()
