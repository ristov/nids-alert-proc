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

if len(sys.argv) != 3:
    print("Usage:", sys.argv[0], "<csv_file> <model_file>", file = sys.stderr)
    sys.exit(0)

training_set = pd.read_csv(sys.argv[1])

X = training_set.drop(columns=['Timestamp', 'SignatureText', 'Label', 'SignatureID', 'Proto', 'ExtIP', 'ExtPort', 'IntIP', 'IntPort'])

y = training_set['Label']

# uncomment the classifier to train

#clf = RandomForestClassifier(n_estimators=100, random_state=1)
#clf = DecisionTreeClassifier(random_state=1)
#clf = AdaBoostClassifier(DecisionTreeClassifier(max_depth=3), n_estimators=100, random_state=1)
#clf = GradientBoostingClassifier(n_estimators=100, max_depth=3, random_state=1)
#clf = make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=50))
#clf = make_pipeline(StandardScaler(), LinearSVC(random_state=1, dual=False))
clf = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=1))

model = clf.fit(X, y)

with open(sys.argv[2], 'wb') as file:
    pickle.dump(model, file)
