#!/usr/bin/env python3

import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
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


def seperate(imports_dict, summary_file):
    summary_df = pd.read_csv(summary_file, usecols=['id', 'list'])
    malware_files = set(summary_df.loc[summary_df['list'] == 'Blacklist']['id'].to_list())
    non_malware_files = set(summary_df.loc[summary_df['list'] == 'Whitelist']['id'].to_list())

    malware_imports = dict()
    non_malware_imports = dict()

    for filename, imports in imports_dict.items():
        try:
            id_ = int(filename)
        except ValueError:
            print(f"invalid {filename}, labeling it as malware", file=sys.stderr)
            malware_imports[filename] = imports
            continue

        if id_ in malware_files:
            malware_imports[filename] = imports
        elif id_ in non_malware_files:
            non_malware_imports[filename] = imports
        else:
            print(f"missing label for {filename}, labeling it as malware", file=sys.stderr)
            malware_imports[filename] = imports

    return malware_imports, non_malware_imports


def get_call_freq(imports_dict):
    c = Counter()
    for import_list in imports_dict.values():
        c.update(import_list)
    return c


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} TRAIN_CSV TRAIN_DICT", file=sys.stderr)
        sys.exit(1)

    train_csv = sys.argv[1]
    train_dict = sys.argv[2]

    imports_data = pre_process.parse_imports_dict(train_dict)
    vocab = pre_process.create_vocab(imports_data)

    call_freq = get_call_freq(imports_data)
    calls = np.array(list(call_freq.keys()))
    freq = np.array(list(call_freq.values()))

    top_n_calls = np.argsort(freq)[::-1]

    malware_imports, non_malware_imports = seperate(imports_data, train_csv)

    malware_call_freq = get_call_freq(malware_imports)
    non_malware_call_freq = get_call_freq(non_malware_imports)

    malware_calls = np.array(list(malware_call_freq.keys()))
    malware_freq = np.array(list(malware_call_freq.values()))

    non_malware_calls = np.array(list(non_malware_call_freq.keys()))
    non_malware_freq = np.array(list(non_malware_call_freq.values()))

    """
    top_n_malware_calls = np.argsort(malware_freq)[::-1]
    top_n_non_malware_calls = np.argsort(non_malware_freq)[::-1]

    print("Most common API imports (malware)")
    for rank, i in enumerate(top_n_malware_calls[:10], 1):
        print(malware_calls[i], malware_freq[i], np.where(calls[top_n_calls] == malware_calls[i])[0][0] + 1, np.where(non_malware_calls[top_n_non_malware_calls] == malware_calls[i])[0][0] + 1, sep='\t')

    print()
    print("Most common API imports (non-malware)")
    for rank, i in enumerate(top_n_non_malware_calls[:10], 1):
        #print(f"{rank}: {non_malware_calls[i]} ({non_malware_freq[i]} times) (overall rank = {np.where(calls[top_n_calls] == non_malware_calls[i])[0]})")
        print(non_malware_calls[i], non_malware_freq[i], np.where(calls[top_n_calls] == non_malware_calls[i])[0][0] + 1, np.where(malware_calls[top_n_malware_calls] == non_malware_calls[i])[0][0] + 1, sep='\t')
    
    # Most Important Features
    import_vectors = pre_process.make_import_vectors(imports_data, vocab)
    filenames = list(import_vectors.keys())
    
    X = list(import_vectors.values())
    y = make_labels(filenames, train_csv)

    model = RandomForestClassifier()
    model.fit(X, y)

    importance = np.array(model.feature_importances_)
    top_n = np.argsort(importance)[-TOP_FEATURES:][::-1]

    print("Top 10 Most Important Features")
    for i in top_n:
        print(vocab.denumberize(i), importance[i], np.where(calls[top_n_calls] == vocab.denumberize(i))[0][0] + 1, np.where(malware_calls[top_n_malware_calls] == vocab.denumberize(i))[0][0] + 1, np.where(non_malware_calls[top_n_non_malware_calls] == vocab.denumberize(i))[0][0] + 1, sep='\t')
    """
    # Top 150 API Call Graph
    
    top_n_calls = top_n_calls[:150]
    X = list(range(len(top_n_calls))) #[calls[i] for i in top_n_calls]
    y_malware = [malware_call_freq[calls[i]] for i in top_n_calls]
    y_non_malware = [non_malware_call_freq[calls[i]] for i in top_n_calls]

    fig, ax = plt.subplots()

    ax.bar(X, y_malware, label='Malware')
    ax.bar(X, y_non_malware, bottom=y_malware, label='Non-Malware')
    ax.legend()

    plt.xlabel("Nth Most Common API Import")
    plt.ylabel("Frequency (training data)")
    plt.title('Distribution of Top API Imports')
    plt.show()


if __name__ == "__main__":
    main()
