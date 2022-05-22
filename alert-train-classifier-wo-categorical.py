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

if len(sys.argv) != 4:
    print("Usage:", sys.argv[0], "<csv_file> <model> <model_file>", 
          file = sys.stderr)
    print("<model> = rf|dt|abdt|gbdt|knn|svml|lr", file = sys.stderr)
    sys.exit(0)

training_set = pd.read_csv(sys.argv[1])

X = training_set.drop(columns=['Timestamp', 'SignatureText', 'Label', 
    'SignatureID', 'Proto', 'ExtIP', 'ExtPort', 'IntIP', 'IntPort'])

y = training_set['Label']

if sys.argv[2] == "rf":
    clf = RandomForestClassifier(n_estimators=100, random_state=1)
elif sys.argv[2] == "dt":
    clf = DecisionTreeClassifier(random_state=1)
elif sys.argv[2] == "abdt":
    clf = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), 
                             n_estimators=100, random_state=1)
elif sys.argv[2] == "gbdt":
    clf = GradientBoostingClassifier(n_estimators=300, max_depth=2, 
                                     random_state=1)
elif sys.argv[2] == "knn":
    clf = make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=50))
elif sys.argv[2] == "svml":
    clf = make_pipeline(StandardScaler(), LinearSVC(random_state=1, dual=False))
elif sys.argv[2] == "lr":
    clf = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, 
                                                             random_state=1))
else:
    print("Unknown model", sys.argv[2], file = sys.stderr)
    sys.exit(1)

model = clf.fit(X, y)

with open(sys.argv[3], 'wb') as file:
    pickle.dump(model, file)
