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
    return c


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} IMPORT_LIST", file=sys.stderr)
        sys.exit(1)

    import_list_file = sys.argv[1]

    imports_dict = parse_imports_dict(import_list_file)

    call_freq = get_call_freq(imports_dict)
    calls = np.array(list(call_freq.keys()))
    freq = np.array(list(call_freq.values()))

    print("Most common API imports")
    top_n = np.argsort(freq)[-10:][::-1]
    for rank, i in enumerate(top_n, 1):
        print(f"{rank}: {calls[i]} ({freq[i]})")

    x = list(range(len(freq)))
    y = sorted(freq)

    plt.bar(x, y, log=True)
    plt.title('API Call Frequency')
    plt.xlabel('API Call')
    plt.ylabel('Frequency')
    plt.show()


if __name__ == "__main__":
    main()

