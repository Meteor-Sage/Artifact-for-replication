import re
import os
import json
import hyper_parameters
from hyper_parameters import root_path
def extract_top_functions_with_xor_shift(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        code = file.read()

    blocks = re.split(r'//----- (.*?) -{20,}', code)

    function_stats = []
    for i in range(1, len(blocks), 2):
        function_body = blocks[i + 1]

        pattern = re.compile(
            r'^\s*[_\w]+\s*\*?\s*(\w+)\s*\([^)]*\)',
            re.DOTALL
        )
        pattern2 = re.compile(
            r'(?:\w+::)?[_\w]+(?:\s*\*+)?\s+(\w+)\s*(?:@<\w+>)?\s*\([^)]*\)',
            re.DOTALL
        )
        function_name_match = re.search(pattern, function_body)
        function_name_match2 = re.search(pattern2, function_body)
        if function_name_match:
            function_name = function_name_match.group(1)
        elif function_name_match2:
            function_name = function_name_match2.group(1)
        else:
            continue


        xor_count = function_body.count('^')
        shift_count = function_body.count('<<') + function_body.count('>>')
        total_count = xor_count + shift_count

        num_lines = function_body.count('\n') + 1
        if num_lines == 0:
            continue

        operation_percentage = total_count / num_lines

        function_stats.append((function_name, total_count, xor_count, shift_count, function_body, operation_percentage))

    function_stats.sort(key=lambda x: x[1], reverse=True)
    top_functions_by_count = function_stats[:int(hyper_parameters.Candidate_n/2)]
    function_stats.sort(key=lambda x: x[5], reverse=True)
    top_functions_by_percentage = function_stats[:int(hyper_parameters.Candidate_n/2)]
    top_function_names_by_count = {func[0] for func in top_functions_by_count}
    top_functions_by_percentage = [func for func in top_functions_by_percentage if func[0] not in top_function_names_by_count]
    combined_top_functions = top_functions_by_count + top_functions_by_percentage
    combined_top_functions.sort(key=lambda x: x[5], reverse=True)

    return combined_top_functions


if __name__ == '__main__':
    subfolders = [f.path for f in os.scandir(root_path) if f.is_dir()]
    for subfolder in subfolders:
        name = os.path.basename(subfolder)

        file_path = os.path.join(subfolder, f'{name}.c')
        top_functions = extract_top_functions_with_xor_shift(file_path)
        output_file = os.path.join(subfolder, f'{name}.txt')

        functions_data = []
        for func in top_functions:
            func_dict = {
                "Function": func[0],
                "Total XOR and shift operations": func[1],
                "XOR operations": func[2],
                "Shift operations": func[3],
                "Operation percentage": f"{func[5]:.2%}",
                "Function Body": func[4]
            }
            functions_data.append(func_dict)

        with open(output_file, 'w', encoding='utf-8') as file:
            json.dump(functions_data, file, indent=4)
