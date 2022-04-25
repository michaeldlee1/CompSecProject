#!/usr/bin/env python3

import os
import sys
import json
from collections import Counter
from vocab import Vocab


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
    v = Vocab()
    for word in [imp for imp, freq in c.most_common(vocab_size)]:
        v.add(word)
    return v


def make_import_vectors(imports_dict, vocab):
    # create one hot vectors for imports
    imports_dict_pre = dict()
    for filename, imports in imports_dict.items():
        # replace low freq imports with "<unk>"
        imports_pre = [imp if imp in vocab else "<unk>" for imp in imports]
        # each column corresponds to the number of API calls that file imports  
        c = Counter(imports_pre)
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

