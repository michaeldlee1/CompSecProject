#!/usr/bin/env python3
# ex:
#   ./train.py data/train.csv imports_train.json data/test.csv imports_test.json

import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.tree import DecisionTreeClassifier 
from sklearn.metrics import accuracy_score
import pre_process


class Model:
    storage_location = 'model.pkl'

    def __init__(self, sklearn_model, vocab):
        self.sklearn_model = sklearn_model
        self.vocab = vocab
    
    def save(self):
        with open(self.storage_location, 'wb') as stream:
            pickle.dump(self, stream)
    
    @classmethod
    def load(cls):
        with open(cls.storage_location, 'rb') as stream:
            return pickle.load(stream)


def make_labels(filenames, summary_file):
    summary_df = pd.read_csv(summary_file, usecols=['id', 'list'])
    malware_files = set(summary_df.loc[summary_df['list'] == 'Blacklist']['id'].to_list())
    non_malware_files = set(summary_df.loc[summary_df['list'] == 'Whitelist']['id'].to_list())

    y = []

    for filename in filenames:
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
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} TRAIN_CSV TRAIN_DICT TEST_CSV TEST_DICT", file=sys.stderr)
        sys.exit(1)

    train_csv = sys.argv[1]
    train_dict = sys.argv[2]
    test_csv = sys.argv[3]
    test_dict   = sys.argv[4]

    imports_data = pre_process.parse_imports_dict(train_dict)
    vocab = pre_process.get_vocab(imports_data)
    import_vectors = pre_process.make_import_vectors(imports_data, vocab)

    filenames = list(import_vectors.keys())
    
    X = list(import_vectors.values())
    y = make_labels(filenames, train_csv)

    model = DecisionTreeClassifier()
    model.fit(X, y)

    m = Model(model, vocab)
    print(f"Saving model to {m.storage_location}")
    m.save()
    
    # run on test set
    import_vectors_test = pre_process.make_import_vectors(pre_process.parse_imports_dict(test_dict), vocab)
    X_test = list(import_vectors_test.values())
    y_true = make_labels(list(import_vectors_test.keys()), test_csv)  
    score = model.score(X_test, y_true)
    print(f"Accuracy: {score:.03f}")


if __name__ == "__main__":
    main()
