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

    # for i in range(len(y)):
    #     features = X.iloc[i].values
    #     label = y.iloc[i]
    #     avg_pred = average_predictions[i]
    #     if label != int(avg_pred > 0.5):
    #         print(
    #             f'name:{data.iloc[i, -1]}, Features: {features}, True Label: {label}, Average Prediction: {int(avg_pred > 0.5)}')

    precision_all = precision_score(y, average_predictions > 0.5, pos_label=0)
    recall_all = recall_score(y, average_predictions > 0.5, pos_label=0)
    y_converted = [1 if label == 0 else 0 for label in y]
    tn, fp, fn, tp = confusion_matrix(y_converted , average_predictions <= 0.5).ravel()

    print(f'True Positives (TP): {tp}')
    print(f'False Positives (FP): {fp}')
    print(f'False Negatives (FN): {fn}')

    print(f'Precision: {precision_all}')
    print(f'Recall: {recall_all}')
    print(f'f1: {2*recall_all*precision_all/(recall_all+precision_all)}')
    print(f'FNR: {fn/(fn+tp)}')


print('BenchmarkA:')
val('./BenchmarkA/process_data.csv')
print('BenchmarkB:')
val('./BenchmarkB/process_data.csv')
print('BenchmarkC:')
val('./BenchmarkC/process_data.csv')