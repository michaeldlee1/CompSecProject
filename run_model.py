#!/usr/bin/env python3

import sys
import numpy
import peExtract
import pre_process
from train import Model


def test_model(filename, model):
    """
    Returns True if predicted malware, False if not, or None if invalid file
    """
    imports = peExtract.extract_file(filename)
    if imports is None:
        return None
    
    imports_vector = numpy.array(pre_process.make_import_vector(imports, model.vocab)).reshape(1, -1)
    y_pred = model.sklearn_model.predict(imports_vector).astype(bool)[0]

    return y_pred


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} MODEL_FILE")
    
    model_file = sys.argv[1]
    model = Model.load(model_file)

    for line in sys.stdin:
        filename = line.strip()
        if test_model(filename, model):
            print(f"{filename}: malware")
        else:
            print(f"{filename}: not malware")


if __name__ == "__main__":
    main()
