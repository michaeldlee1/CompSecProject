#!/usr/bin/env python3

import sys
import json
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
from vocab import Vocab, save_vocab


def parse_imports_dict(filename):
    with open(filename, 'r') as stream:
        imports = json.load(stream)
    return imports


def get_call_freq(imports_dict):
    c = Counter()
    for import_list in imports_dict.values():
        c.update(import_list)
    return np.array(list(c.values()))


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} IMPORT_LIST", file=sys.stderr)
        sys.exit(1)

    import_list_file = sys.argv[1]

    imports_dict = parse_imports_dict(import_list_file)

    freq = get_call_freq(imports_dict)
    plt.hist(freq, bins=100, log=True)
    """
    x = list(range(len(freq)))
    y = sorted(freq)
    plt.bar(x, y, log=True)
    """
    plt.show()


if __name__ == "__main__":
    main()

