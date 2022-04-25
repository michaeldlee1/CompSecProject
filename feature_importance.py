#!/usr/bin/env python3
# ex:
#   ./feature_importance.py data/train.csv imports_train.json.pre imports_train.json.vocab

import os
import sys
import json
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier 
from sklearn.metrics import accuracy_score
from vocab import Vocab
from pre_process import parse_imports_dict, make_import_vectors


TOP_FEATURES = 200


def read_vocab(filename):
    vocab = Vocab()
    with open(filename, 'r') as stream:
        for line in stream:
            vocab.add(line.strip())
    return vocab


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
        print(f"Usage: {sys.argv[0]} SUMMARY_CSV IMPORTS_DICT VOCAB_FILE", file=sys.stderr)
        sys.exit(1)

    summary_path = sys.argv[1]
    imports_file = sys.argv[2]
    vocab_file   = sys.argv[3]

    imports_data = parse_imports_dict(imports_file)
    imports = list(imports_data.keys())
    
    X = list(imports_data.values())
    y = make_labels(imports, summary_path)

    model = DecisionTreeClassifier()
    model.fit(X, y)

    vocab = read_vocab(vocab_file)

    importance = np.array(model.feature_importances_)
    top_n = np.argsort(importance)[-TOP_FEATURES:][::-1]
    for rank, i in enumerate(top_n, 1):
        print(f"{rank}: {vocab.denumberize(i)} ({importance[i]})")

    """
    # run on test set
    import_vectors = make_import_vectors(parse_imports_dict('imports_test.json'), vocab)
    X_test = list(import_vectors.values())
    y_true = make_labels(list(import_vectors.keys()), 'data/test.csv')  
    score = model.score(X_test, y_true)
    print(score)
    """



if __name__ == "__main__":
    main()

