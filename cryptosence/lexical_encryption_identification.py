import os
import extract_functions_with_keyword
from hyper_parameters import root_path, keyword_file

# lexical_encryption_identification.py  ->  candidate_function_selection.py  ->  semantic_encryption_identification.py  -> gen_garph.py  ->  dangerous_flow_generation.py ->  backward_taint_analysis.py -> severity_level.py -> feature.py
# logistic_regression_train.py
# logistic_regression_predict.py
if __name__ == '__main__':
    keywords = extract_functions_with_keyword.read_keywords_from_csv(keyword_file)
    subfolders = [f.path for f in os.scandir(root_path) if f.is_dir()]
    all_res = []
    all_counts = {}
    for subfolder in subfolders:
        name = os.path.basename(subfolder)

        file_path = os.path.join(subfolder, name + '.c')
        output_file = os.path.join(subfolder, name + '.csv')

        if os.path.exists(file_path):
            results = extract_functions_with_keyword.extract_functions_with_keywords(file_path, keywords)
            all_res.append(results)
            extract_functions_with_keyword.write_results_to_csv(results, output_file)
        else:
            print(f"File {file_path} does not exist.")

    for res in all_res:
        counts = {}
        for item in res:
            for _item in res[item]:
                for key in _item[3]:
                    if key not in counts:
                        counts[key] = 1
        for item in counts:
            if item not in all_counts:
                all_counts[item] = 1
            else:
                all_counts[item] += 1

    print(all_counts)