#!/usr/bin/env python3
# ex:
#   ./train2.py imports_full.json data/full.csv

import os
import sys
import pickle
import numpy as np
import pandas as pd
from statistics import mean
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import accuracy_score, precision_score, recall_score
from sklearn.model_selection import KFold
import pre_process


models = [
    DecisionTreeClassifier(),
    RandomForestClassifier(),
    AdaBoostClassifier(),
    GaussianNB()
]

model_names = [
    'Decision Tree',
    'Random Forest',
    'AdaBoost',
    'Naive Bayes'
]


class Model:
    model_dir = 'models'

    def __init__(self, sklearn_model, vocab):
        self.sklearn_model = sklearn_model
        self.vocab = vocab
    
    def save(self, name):
        path = os.path.join(self.model_dir, name)
        with open(path, 'wb') as stream:
            pickle.dump(self, stream)
    
    @classmethod
    def load(cls, name):
        path = os.path.join(cls.model_dir, name)
        with open(path, 'rb') as stream:
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

    return np.array(y)


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} IMPORTS_DICT SUMMARY", file=sys.stderr)
        sys.exit(1)

    imports_dict_file = sys.argv[1]
    summary_file = sys.argv[2]

    imports_dict = pre_process.parse_imports_dict(imports_dict_file)

    filenames = np.array(list(imports_dict.keys()))                 # ['1', '2', ... ]
    imports = np.array(list(imports_dict.values()), dtype=object)   # [['a', 'b', ... ], ['b', 'c', ... ], ... ]
    labels = make_labels(filenames, summary_file)                   # [1, 0, ... ]

    kfold = KFold(5)

    for model, model_name in zip(models, model_names):
        print(model_name)
        accuracy = []
        precision = []
        recall = []

        for train_index, test_index in kfold.split(imports):
            imports_train = imports[train_index]
            labels_train = labels[train_index]

            vocab = pre_process.create_vocab(imports_train)
            imports_vector_train = pre_process.make_import_vectors_2(imports_train, vocab)

            model.fit(imports_vector_train, labels_train)

            imports_test  = imports[test_index]
            imports_vector_test = pre_process.make_import_vectors_2(imports_test, vocab)
            labels_test = labels[test_index]

            pred_test = model.predict(imports_vector_test)

            accuracy.append(accuracy_score(labels_test, pred_test))
            precision.append(precision_score(labels_test, pred_test))
            recall.append(recall_score(labels_test, pred_test))
        
        print("\tAccuracy:", accuracy, mean(accuracy))
        print("\tPrecision:", precision, mean(precision))
        print("\tRecall:", recall, mean(recall))


if __name__ == "__main__":
    main()

