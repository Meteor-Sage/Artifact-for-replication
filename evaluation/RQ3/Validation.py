import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import joblib

def val(path):
    data = pd.read_csv(path, header=None)
    X = data.iloc[:, :-2]
    y = data.iloc[:, -2]
    X.iloc[:, -1] = X.iloc[:, -1].astype(bool).astype(int)
    classifiers = joblib.load('logistic_regression_models.joblib')
    sample_predictions = np.zeros((len(y), len(classifiers)))


    for i, classifier in enumerate(classifiers):
        y_pred = classifier.predict(X)
        sample_predictions[:, i] = y_pred

    average_predictions = sample_predictions.mean(axis=1)


    y_converted = [1 if label == 0 else 0 for label in y]
    tn, fp, fn, tp = confusion_matrix(y_converted , average_predictions <= 0.5).ravel()

    print(f'True Positives (TP): {tp}')
    print(f'False Negatives (FN): {fn}')
    print(f'FNR: {fn/(fn+tp)}')



print('Kreuk:')
val('./data/Kreuk/process_data.csv')

print('IPR:')
val('./data/IPR/process_data.csv')

print('DISP:')
val('./data/DISP/process_data.csv')