import json
import os
import extract_graph
import csv
from hyper_parameters import root_path

subfolders = [f.path for f in os.scandir(root_path) if f.is_dir()]

for subfolder in subfolders:
    name = os.path.basename(subfolder)
    file_path1 = os.path.join(subfolder, name + '.csv')
    file_path2 = os.path.join(subfolder, name + '.txt')
    file_path3 = os.path.join(subfolder, name + '_results.json')
    functions = extract_graph.read_keywords_from_csv(file_path1)
    fun_org = []
    fun_cry = []
    fun_cry_out = []

    with open(file_path2, 'r', encoding='utf-8') as file:
        content = json.load(file)
    for fun in content:
        fun_org.append(fun['Function'])
    with open(file_path3, 'r', encoding='utf-8') as file:
        content = json.load(file)
    for fun in content:
        if fun['content_modification_operations']['is_crypto_fun']:
            fun_cry.append((fun['content_modification_operations']['fun_name'], fun['content_modification_operations']['description']))
    for fun1 in fun_org:
        for fun2 in fun_cry:
            if fun1 in fun2[0]:
                if fun1 not in functions['crypt_function']:
                    functions['crypt_function'].append(fun1)
                    functions['crypt_keyword'].append(fun2[1])

        max_length = max(len(lst) for lst in functions.values())

        csv_data = []
        headers = list(functions.keys())
        csv_data.append(headers)


        for i in range(max_length):
            row = []
            for key in headers:
                row.append(functions[key][i] if i < len(functions[key]) else '')
            csv_data.append(row)

        with open(file_path1, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(csv_data)


