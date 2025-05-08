import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score

Ablation=['w_o_Unpacking','w_o_Compile_and_Decompile','w_o_EEI_Lex','w_o_EEI_Lex_(C)','w_o_EEI_Lex_(N)','w_o_EEI_Sem','w_o_EEI_Sem_(DB)','w_GPT3.5','w_DeepSeek','w_o_LLM']

for type in Ablation:
    file_path = f'{type}.csv'
    df = pd.read_csv(file_path)

    y_true = df['Ground_truth']
    y_pred = df['Predicted']

    precision = precision_score(y_true, y_pred, pos_label=0)
    recall = recall_score(y_true, y_pred, pos_label=0)
    f1 = f1_score(y_true, y_pred, pos_label=0)
    print(f'\n{type}:')
    print(f'Precision: {precision}')
    print(f'Recall: {recall}')
    print(f'F1 Score: {f1}')
