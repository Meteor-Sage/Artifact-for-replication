import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, confusion_matrix
import joblib


data = pd.read_csv('features_predict.csv', header=None)
X = data.iloc[:, :-2]
y = data.iloc[:, -2]
X.iloc[:, -1] = X.iloc[:, -1].astype(bool).astype(int)
classifiers = joblib.load('logistic_regression_models.joblib')
sample_predictions = np.zeros((len(y), len(classifiers)))
for i, classifier in enumerate(classifiers):
    y_pred = classifier.predict(X)
    sample_predictions[:, i] = y_pred

average_predictions = sample_predictions.mean(axis=1)
for i in range(len(y)):
    features = X.iloc[i].values
    label = y.iloc[i]
    avg_pred = average_predictions[i]
    if label != int(avg_pred > 0.5):
        print(
            f'name:{data.iloc[i, -1]}, Features: {features}, True Label: {label}, Average Prediction: {int(avg_pred > 0.5)}')

accuracy_all = accuracy_score(y, average_predictions > 0.5)
precision_all = precision_score(y, average_predictions > 0.5, pos_label=0)
recall_all = recall_score(y, average_predictions > 0.5, pos_label=0)
tn, fp, fn, tp = confusion_matrix(y, average_predictions > 0.5).ravel()

print(f'Average Accuracy: {accuracy_all:.2f}')
print(f'Average Precision: {precision_all:.2f}')
print(f'Average Recall: {recall_all:.2f}')
print(f'Average True Negatives (TN): {tn:.2f}')
print(f'Average False Positives (FP): {fp:.2f}')
print(f'Average False Negatives (FN): {fn:.2f}')
print(f'Average True Positives (TP): {tp:.2f}')
