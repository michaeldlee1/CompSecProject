#!/usr/bin/env python3
# ex:
#   ./feature_importance.py data/train.csv imports_train.json

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import pre_process


TOP_FEATURES = 10


def make_labels(imports, summary_file):
    summary_df = pd.read_csv(summary_file, usecols=['id', 'list'])
    malware_files = set(summary_df.loc[summary_df['list'] == 'Blacklist']['id'].to_list())
    non_malware_files = set(summary_df.loc[summary_df['list'] == 'Whitelist']['id'].to_list())

    y = []

    for filename in imports:
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

    return y


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} SUMMARY_CSV IMPORTS_DICT", file=sys.stderr)
        sys.exit(1)

    summary_path = sys.argv[1]
    imports_file = sys.argv[2]

    imports_data = pre_process.parse_imports_dict(imports_file)
    vocab = pre_process.create_vocab(imports_data.values())

    import_vectors = pre_process.make_import_vectors(imports_data, vocab)
    filenames = list(import_vectors.keys())
    
    X = list(import_vectors.values())
    y = make_labels(filenames, summary_path)

    model = RandomForestClassifier()
    model.fit(X, y)

    importance = np.array(model.feature_importances_)
    top_n = np.argsort(importance)[-TOP_FEATURES:][::-1]
    for i in top_n:
        print(vocab.denumberize(i), importance[i], sep='\t')


if __name__ == "__main__":
    main()
