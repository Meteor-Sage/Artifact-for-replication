
import os
import pickle
import csv
import re



def process_data(root_path, label):

    bench = root_path
    if label == 0:
        root_path += "Ransomware/"
    else:
        root_path += "Benign/"

    subfolders = [f.path for f in os.scandir(root_path) if f.is_dir()]
    for subfolder in subfolders:
        name = os.path.basename(subfolder)
        if not os.path.exists(root_path + name + '/' + "crypt_function") and not os.path.exists(root_path + name + '/' + "danger_word_function"):
            with open(f"{bench}process_data.csv", mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(
                    [100, 0, 100, 0, False, label, name])
            continue
        dataflow1 = []
        dataflow_pub1 = []
        dataflow2 = []
        dataflow_pub2 = []
        dataflow3 = []
        dataflow_pub3 = []
        res = []
    
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
            with open(f"{bench}process_data.csv", mode='a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(
                    [100, 0, 100, 0, False, label,name])
            continue
    
    
        with open(f"{bench}process_data.csv", mode='a', newline='') as file:
            writer = csv.writer(file)
    
            writer.writerow(
                [fun_count, fun_Malicious_count, fun_Benign_count, fun_Neutral_count, data_source_same > 0, label,name])





process_data("./BenchmarkA/", 1)
process_data("./BenchmarkA/", 0)
process_data("./BenchmarkB/", 1)
process_data("./BenchmarkB/", 0)
process_data("./BenchmarkC/", 1)
process_data("./BenchmarkC/", 0)


