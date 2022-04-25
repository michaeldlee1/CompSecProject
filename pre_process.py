#!/usr/bin/env python3

import os
import sys
import json
from collections import Counter


VOCAB_SIZE = 2000


def parse_imports_dict(filename):
    with open(filename, 'r') as stream:
        imports = json.load(stream)
    return imports


def get_vocab(imports_dict, vocab_size=VOCAB_SIZE):
    # create vocab with "vocab_size" most common imports
    c = Counter()
    for import_list in imports_dict.values():
        c.update(import_list)
    return {imp for imp, freq in c.most_common(vocab_size)} | {'<unk>'}


def make_import_vectors(imports_dict, vocab):
    # replace low freq imports with "<unk>"
    imports_dict_unk = dict()
    for filename in imports_dict:
        imports_dict_unk[filename] = [imp if imp in vocab else '<unk>' for imp in imports_dict[filename]]

    # create one hot vectors for imports
    imports_dict_pre = dict()
    for filename, imports in imports_dict_unk.items():
        c = Counter(imports)
        imports_dict_pre[filename] = [c[imp] for imp in vocab]

    return imports_dict_pre


def save_vocab(vocab, stream):
    for imp in vocab:
        print(imp, file=stream)


def save_preprocessed_imports(imports, stream):
    print(json.dumps(imports), file=stream)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} IMPORT_LIST", file=sys.stderr)
        sys.exit(1)

    import_list_file = sys.argv[1]

    imports_dict = parse_imports_dict(import_list_file)
    vocab = get_vocab(imports_dict)
    imports_dict = make_import_vectors(imports_dict, vocab)

    with open(import_list_file + ".pre", 'w') as stream:
        save_preprocessed_imports(imports_dict, stream)

    with open(import_list_file + ".vocab", 'w') as stream:
        save_vocab(vocab, stream)


if __name__ == "__main__":
    main()

