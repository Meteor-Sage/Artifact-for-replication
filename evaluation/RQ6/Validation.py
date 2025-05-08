import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import MaxNLocator
import json

# 读取数据
with open('results_Top_n_Candidate.json', 'r') as f:
    results = json.load(f)

f1_scores = [result['f1score'] for result in results]
x_all = np.arange(0, 40)

# 创建图像
plt.figure(figsize=(10, 5))
plt.plot(x_all, f1_scores, label='F1-score', marker='.')
plt.xlabel('Top n Candidate')
plt.ylabel('Percentage')
plt.legend()
plt.gca().xaxis.set_major_locator(MaxNLocator(integer=True))

# 保存为 PDF
plt.savefig('Fig9.pdf')

# 显示图像
plt.show()
