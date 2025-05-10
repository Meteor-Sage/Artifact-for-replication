import os
from hyper_parameters import root_path
import pickle
import csv
import hyper_parameters
import re

if __name__ == '__main__':
    benign_count = 0
    ransom_count = 0
    count = 0
    subfolders = [f.path for f in os.scandir(root_path) if f.is_dir()]
    with open('features.csv', mode='w', newline='') as file:
        pass
    for subfolder in subfolders:
        count += 1
        name = os.path.basename(subfolder)
        print(name + ":__________________________________")
        if not os.path.exists(root_path + name + '/' + "crypt_function") and not os.path.exists(root_path + name + '/' + "danger_word_function"):
            benign_count += 1
            print("res-benign")
            with open(root_path + name + '/' +name+'.c', 'r', encoding='utf-8', errors='ignore') as file:
                code = file.read()
            blocks = re.split(r'//----- (.*?) -{20,}', code)
            with open('features.csv', mode='a', newline='') as file:
                writer = csv.writer(file)
                if len(blocks) > 500:
                    len_ = 500
                writer.writerow(
                    [len_, 0, len_, 0, False, hyper_parameters.sample_label, name])
            continue
        dataflow1=[]
        dataflow_pub1=[]
        dataflow2=[]
        dataflow_pub2=[]
        dataflow3=[]
        dataflow_pub3=[]
        res=[]

        try:
            with open(root_path + name + '/' + name + ".pkl", 'rb') as file:
                dataflow1, dataflow_pub1, dataflow2, dataflow_pub2, dataflow3, dataflow_pub3, res = pickle.load(file)
        except:
            pass

        try:
            with open(root_path + name + '/' + name + "_other.pkl", 'rb') as file:
                dataflow1, dataflow_pub1, dataflow2, dataflow_pub2, dataflow3, dataflow_pub3 = pickle.load(file)
        except:
            pass

        fun_count = 0
        fun_Benign_count = 0
        fun_Neutral_count = 0
        fun_Malicious_count = 0
        data_source_same = 0

        for fun in dataflow1:
            fun_count += 1
            if fun[1]["Taint_Analysis"]["danger"] == "Malicious" or fun[1]["Taint_Analysis"]["danger"] == "malicious":
                fun_Malicious_count += 1
            elif fun[1]["Taint_Analysis"]["danger"] == "Benign" or fun[1]["Taint_Analysis"]["danger"] == "Benign":
                fun_Benign_count += 1
            else:
                fun_Neutral_count += 1

        for fun in dataflow2:
            fun_count += 1
            if fun[1]["Taint_Analysis"]["danger"] == "Malicious" or fun[1]["Taint_Analysis"]["danger"] == "malicious":
                fun_Malicious_count += 1
            elif fun[1]["Taint_Analysis"]["danger"] == "Benign" or fun[1]["Taint_Analysis"]["danger"] == "Benign":
                fun_Benign_count += 1
            else:
                fun_Neutral_count += 1

        for fun in dataflow3:
            fun_count += 1
            if fun[1]["Taint_Analysis"]["danger"] == "Malicious" or fun[1]["Taint_Analysis"]["danger"] == "malicious":
                fun_Malicious_count += 1
            elif fun[1]["Taint_Analysis"]["danger"] == "Benign" or fun[1]["Taint_Analysis"]["danger"] == "Benign":
                fun_Benign_count += 1
            else:
                fun_Neutral_count += 1

        for fun in res:
            fun_count += 1
            if fun[1]["Taint_Analysis"]["danger"] == "Malicious" or fun[1]["Taint_Analysis"]["danger"] == "malicious":
                fun_Malicious_count += 1
            elif fun[1]["Taint_Analysis"]["danger"] == "Benign" or fun[1]["Taint_Analysis"]["danger"] == "Benign":
                fun_Benign_count += 1
            else:
                fun_Neutral_count += 1
            if fun[1]["Taint_Analysis"]["is_data_sources_same"]:
                data_source_same += 1

        if fun_count==0 and  fun_Malicious_count==0 and fun_Benign_count == 0 and fun_Neutral_count ==0:
            with open(root_path + name + '/' +name+'.c', 'r', encoding='utf-8', errors='ignore') as file:
                code = file.read()
            blocks = re.split(r'//----- (.*?) -{20,}', code)
            with open('output.csv', mode='a', newline='') as file:
                writer = csv.writer(file)
                len_ = len(blocks)
                if len(blocks) > 500:
                    len_ = 500
                writer.writerow(
                    [len_, 0, len_, 0, False, hyper_parameters.sample_label,name])
            continue


        with open('features.csv', mode='a', newline='') as file:
            writer = csv.writer(file)

            writer.writerow(
                [fun_count, fun_Malicious_count, fun_Benign_count, fun_Neutral_count, data_source_same > 0, hyper_parameters.sample_label,name])

        if data_source_same > 0:
            ransom_count += 1
            continue

        if fun_Malicious_count == 0:
            benign_count += 1
            continue

        ransom_count += 1






