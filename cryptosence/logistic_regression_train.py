import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import numpy as np
import time
import joblib

if __name__ == '__main__':
    data = pd.read_csv('features_train.csv', header=None)
    X = data.iloc[:, :-2]
    y = data.iloc[:, -2]
    X.iloc[:, -1] = X.iloc[:, -1].astype(bool).astype(int)
    accuracy_all = 0
    precision_all = 0
    recall_all = 0
    tn_all = 0
    fp_all = 0
    fn_all = 0
    tp_all = 0
    num_epoch = 100
    sample_predictions = np.zeros((len(y), num_epoch))
    classifiers = []
    for i in range(num_epoch):
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.5, random_state=i)
        classifier = LogisticRegression()
        start_time = time.time()
        classifier.fit(X_train, y_train)
        end_time = time.time()
        all_time = end_time - start_time
        classifiers.append(classifier)
        y_pred = classifier.predict(X_test)
        for idx, pred in zip(y_test.index, y_pred):
            sample_predictions[idx, i] = pred

        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred, pos_label=0)
        recall = recall_score(y_test, y_pred, pos_label=0)

        accuracy_all += accuracy
        precision_all += precision
        recall_all += recall

        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        tn_all += tn
        fp_all += fp
        fn_all += fn
        tp_all += tp

    joblib.dump(classifiers, 'logistic_regression_models.joblib')
    average_predictions = sample_predictions.mean(axis=1)

