import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import LinearSVC
from sklearn.linear_model import LogisticRegression

from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

import pickle
import sys
import csv
import json

if len(sys.argv) != 2:
    print("Usage:", sys.argv[0], "<model_file>", file = sys.stderr)
    sys.exit(0)

with open(sys.argv[1], 'rb') as file:
    model = pickle.load(file)

csvfile = csv.reader(sys.stdin)

headers = next(csvfile)

# since several implementations of pandas.DataFrame.to_json() method have
# memory leak issues (https://github.com/pandas-dev/pandas/issues/43877),
# pandas.DataFrame.to_dict() and json.dumps() methods are used for producing
# the output

for fields in csvfile:
    df = pd.DataFrame([fields], columns=headers)
    X = df.drop(columns=['Timestamp', 'SignatureText', 'Label', 'SignatureID', 'Proto', 'ExtIP', 'ExtPort', 'IntIP', 'IntPort'])
    result = model.predict(X)
    df['Label2'] = result[0]
    temp = df.to_dict(orient="records")
    print(json.dumps(temp[0]))
