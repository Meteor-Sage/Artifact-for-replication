import pandas as pd
import numpy as np

methods = ['GREEDYBLOCK', 'GREEDY', 'Random_Forest', 'ZRS', 'CRYPTOSENSE']

for method in methods:
    df = pd.read_csv(f'time_{method}.csv')
    times = df['time/s']
    print(f'{method}:{np.mean(times)}s')

df = pd.read_csv(f'cost_CRYPTOSENSE.csv')
total_tokens = np.sum(df['tokens/k'])
pre_cost = np.mean(df['cost/$'])
print(f'CRYPTOSENSE generates {total_tokens}k tokens for the entire testing dataset of 258 samples from Benchmark C. Based on token usage rates as of May 2025, CRYPTOSENSE approximately cost ${pre_cost} per sample.')
