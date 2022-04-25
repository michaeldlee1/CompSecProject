#!/usr/bin/env python3
# ex:
#   ./feature_importance.py data/train.csv imports_train.json.pre imports_train.json.vocab

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeRegressor


TOP_FEATURES = 200


def read_vocab(filename):
    vocab = list()
    with open(filename, 'r') as stream:
        return [line.strip() for line in stream]


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} SUMMARY IMPORTS VOCAB", file=sys.stderr)
        sys.exit(1)

    summary_path = sys.argv[1]
    imports_file = sys.argv[2]
    vocab_file   = sys.argv[3]

    with open(imports_file, 'r') as stream:
        imports_data = json.load(stream)

    summary_df = pd.read_csv(summary_path, usecols=['id', 'list'])
    malware_files = set(summary_df.loc[summary_df['list'] == 'Blacklist']['id'].to_list())
    non_malware_files = set(summary_df.loc[summary_df['list'] == 'Whitelist']['id'].to_list())

    vocab = read_vocab(vocab_file)

    X = [imp for imp in imports_data.values()]
    y = []

    for filename in imports_data:
        try:
            id_ = int(filename)
        except ValueError:
            print(f"invalid {filename}, labeling it as malware", file=sys.stderr)
            y.append(1)
            continue

        if id_ in malware_files:
            y.append(1)
        elif id_ in non_malware_files:
            y.append(0)
        else:
            print(f"missing label for {filename}, labeling it as malware", file=sys.stderr)
            y.append(1)

    model = DecisionTreeRegressor()
    model.fit(X, y)

    importance = np.array(model.feature_importances_)
    top_n = np.argsort(importance)[-TOP_FEATURES:][::-1]
    for rank, i in enumerate(top_n, 1):
        print(f"{rank}: {vocab[i]} ({importance[i]})")


if __name__ == "__main__":
    main()

