from openai import OpenAI
import json
import os
import re
from collections import defaultdict, deque
import concurrent.futures
import hyper_parameters
from hyper_parameters import root_path


clients = [OpenAI(base_url=params["base_url"], api_key=params["api_key"], timeout=params["timeout"]) for params in hyper_parameters.api_parameters]
executors = [concurrent.futures.ThreadPoolExecutor(max_workers=hyper_parameters.max_workers) for _ in clients]
current_client_index = 0


def find_leaf_order(edges):
    graph = defaultdict(list)
    out_degree = defaultdict(int)
    for u, v in edges:
        graph[u].append(v)
        out_degree[u] += 1
        if v not in out_degree:
            out_degree[v] = 0
    queue = deque([node for node in out_degree if out_degree[node] == 0])
    leaf_order = []

    while queue:
        leaf = queue.popleft()
        leaf_order.append(leaf)

        for node in list(graph):
            if leaf in graph[node]:
                graph[node].remove(leaf)
                out_degree[node] -= 1
                if out_degree[node] == 0:
                    queue.append(node)

    return leaf_order


def analyze_function(type, orders):
    global current_client_index
    dataflow = []
    dataflow_pub = []

    for order in orders:

        body = function_dict.get(order, "Function not found")
        if body == "Function not found":
            continue

        public_variable_single = []
        import_names_single = []
        for var_name in variable_names:
            if var_name in body:
                public_variable_single.append(var_name)
        for import_name in import_names:
            if import_name in body:
                import_names_single.append(import_name)
        if order in org_leafs[type-1]:
            if type == 1:
                    des = "read/create"
            elif type == 3:
                    des = "write/delete"
            else:
                des = "encryption"

            for i in range(3):
                try:
                    client = clients[current_client_index]
                    current_client_index = (current_client_index + 1) % len(executors)
                    response = client.chat.completions.create(
                        model="gpt-4o",
                        messages=[
                                {"role": "system",
                                 "content": "You are now a code analyst and decompilation expert, familiar with various encryption algorithms, the principles of ransomware, and the results of decompiled code."},
                                {"role": "user",
                                 "content": f'''
                                     You are provided with a sequence of decompiled functions. Your tasks are as follows:
                                     Rules and conditions:
                                     1)Identify the location of file data behavior {des} in the code.
                                     2)If the code exhibits data {des} behavior,Reverse trace the flow of file data/filenames to analyze their sources, determining if they originate from global variables or passed parameters.
                                     3)Analyze the severity level of the function to determine if it potentially originates from malicious ransomware, and classify it as one of the three levels: Benign, Neutral, or Malicious.
                                     4)The output should be in JSON format. Here are two example outputs,Please note that global_variable and parameter are variables related to the {des} data behavior obtained through taint analysis. They are not necessarily all global variables and input parameters:
                                     "Taint_Analysis": {{
                                        "fun_name": "sub_12345(v1, v2, v3)",
                                        "global_variable": ["a9","a18"],
                                        "parameter": ["v2"],
                                        "danger": "Malicious",
                                        "description": "Through data flow analysis, global variables a9 and a18 are identified as sources of file data, and input parameter v2 is also a source of file data. The data flow is as follows: a1->a10->a9, a1->a18, a1->c6->v2. The function involves potential malicious behaviors A, B, C, and the threat level is classified as Malicious."
                                     }},
                                     "Taint_Analysis": {{
                                        "fun_name": "sub_123456(v1)",
                                        "global_variable": "[]",
                                        "parameter": "[]",
                                        "danger": "Benign",
                                        "description": "Upon analysis, there is no file data {des} behavior. The function exhibits no obvious malicious behavior."
                                     }}
                                     5) If you are ready, please reply 'Understood'.
                                     '''},
                                {"role": "assistant", "content": "Understood"},
                                {"role": "user",
                                 "content": f"fun_name:{order}\nglobal variable:{public_variable_single}\nexternal function import:{import_names_single}\nfunction body:\n{body}"},
                            ]
                        )
                    message_content = response.choices[0].message.content
                    match = re.search(r'```json\s*(\{.*?\})\s*```', message_content, re.DOTALL)
                    if match:
                        json_content = match.group(1).strip()
                        parsed_json = json.loads(json_content)
                        dataflow.append((order, parsed_json))
                        dataflow_pub = list(set(dataflow_pub + parsed_json['Taint_Analysis']['global_variable']))
                        break
                except:
                    pass

        else:
            other_funs = []
            target_pub = []
            for _dataflow in dataflow:
                if _dataflow[0] in body:
                    other_funs.append((_dataflow[1]['Taint_Analysis']['fun_name'], _dataflow[1]['Taint_Analysis']['parameter']))
            for _dataflow_pub in dataflow_pub:
                if _dataflow_pub in body:
                    target_pub.append(_dataflow_pub)

            for i in range(3):
                try:
                    client = clients[current_client_index]
                    current_client_index = (current_client_index + 1) % len(executors)
                    response = client.chat.completions.create(
                        model="gpt-4o",
                        messages=[
                                {"role": "system",
                                 "content": "You are now a code analyst and decompilation expert, familiar with various encryption algorithms, the principles of ransomware, and the results of decompiled code."},
                                {"role": "user",
                                 "content": f'''
                                    Your task is to analyze a decompiled function using the concept of reverse taint analysis to identify the source of data.
                                    Rules and conditions:
                                    1)In the previous analysis, it is known that tainted data exists in some global variables, functions and their corresponding parameters.
                                    2)The aforementioned functions or global variables are referenced in this function. Please reverse trace the data flow and analyze the data sources, i.e., determine which global variables or input parameters they might originate from.
                                    3)Analyze the severity level of the function to determine if it potentially originates from malicious ransomware, and classify it as one of the three levels: Benign, Neutral, or Malicious.
                                    4)The output should be in JSON format. Here are two example outputs,Please note that global_variable and parameter are variables obtained through taint analysis. They are not necessarily all global variables and input parameters:
                                    "Taint_Analysis": {{
                                        "fun_name": "sub_12345(v1, v2, v3)",
                                        "global_variable": ["a9","a18"],
                                        "parameter": ["v2"],
                                        "danger": "Malicious",
                                        "description": "Through data flow analysis, global variables a9 and a18 are identified as sources of data, and input parameter v2 is also a source of data. The data flow is as follows: a1->a10->a9, a1->a18, a1->c6->v2. The function involves potential malicious behaviors A, B, C, and the threat level is classified as Malicious."
                                    }},
                                    "Taint_Analysis": {{
                                        "fun_name": "sub_123456(v1)",
                                        "global_variable": "[]",
                                        "parameter": "[]",
                                        "danger": "Benign",
                                        "description": "Upon analysis, there is no global variables or parameters that are tainted. The function exhibits no obvious malicious behavior."
                                    }}
                                    5) If you are ready, please reply 'Understood'.
                                    '''},
                                {"role": "assistant", "content": "Understood"},
                                {"role": "user",
                                 "content": f"fun_name:{name}\nall_global_variables_used_in_this_function:{public_variable_single}\nexternal function import:{import_names_single}\ntainted_functions_and_parameters:{other_funs}\ntainted_global_variables:{target_pub}\nfunction_body:\n{body}"},
                            ]
                        )

                    message_content = response.choices[0].message.content
                    match = re.search(r'```json\s*(\{.*?\})\s*```', message_content, re.DOTALL)
                    if match:
                        json_content = match.group(1).strip()
                        parsed_json = json.loads(json_content)
                        dataflow.append((order, parsed_json))
                        dataflow_pub = list(set(dataflow_pub + parsed_json['Taint_Analysis']['global_variable']))
                        break
                except:
                    pass

    return dataflow, dataflow_pub


def analyze_function_join(dataflow1, dataflow_pub1, dataflow2,dataflow_pub2,dataflow3,dataflow_pub3):
    global current_client_index
    res = []
    for leaf_123 in content['sub_123']['leafs']:
        body = function_dict.get(leaf_123, "Function not found")
        if body == "Function not found":
            continue
        fun_1 = [(item[1]['Taint_Analysis']['fun_name'], item[1]['Taint_Analysis']['parameter']) for item in dataflow1 if item[0] in body]
        pub_1 = [item for item in dataflow_pub1 if item in body]
        fun_2 = [(item[1]['Taint_Analysis']['fun_name'], item[1]['Taint_Analysis']['parameter']) for item in dataflow2 if item[0] in body]
        pub_2 = [item for item in dataflow_pub2 if item in body]
        fun_3 = [(item[1]['Taint_Analysis']['fun_name'], item[1]['Taint_Analysis']['parameter']) for item in dataflow3 if item[0] in body]
        pub_3 = [item for item in dataflow_pub3 if item in body]

        import_names_single = [item for item in import_names if item in body]
        for i in range(3):
            try:
                client = clients[current_client_index]
                current_client_index = (current_client_index + 1) % len(executors)
                response = client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                            {"role": "system",
                             "content": "You are now a code analyst and decompilation expert, familiar with various encryption algorithms, the principles of ransomware, and the results of decompiled code."},
                            {"role": "user",
                             "content": f'''
                                Your task is to analyze a decompiled function using the concept of reverse taint analysis to identify the source of file data.
                                Rules and conditions:
                                1)the "is_convergent_function" flag identifies the convergent function. Valid encryption behavior sequences include:  RD->EN, EN->DL, EN->WR, ... Determine whether the tainted statements follow one of these valid encryption patterns and originate from a consistent data source.
                                2)It is known that ransomware performs read, encrypt, and delete operations on files. Therefore, identifying whether the data sources or file handles for these three operations are the same is crucial.
                                3)Use data flow analysis to determine whether the file data or file handles corresponding to these three operations originate from the same source.
                                4)In previous analyses, we obtained the other functions or global variables corresponding to the file read, file encryption, and file deletion operations separately.In addition, if this function also includes similar operations, it should also be included in the analysis data.
                                5)Analyze the severity level of the function to determine if it potentially originates from malicious ransomware, and classify it as one of the three levels: Benign, Neutral, or Malicious.
                                6)The output should be in JSON format. Here are two example outputs. Please note that if it is determined that the three operations originate from the same data source, provide the data flow as evidence.
                                    "Taint_Analysis": {{
                                        "fun_name": "sub_12345(v1, v2, v3)",
                                        "is_data_sources_same": true,
                                        "danger": "Malicious",
                                        "description": "Through data flow analysis, The data flow is as follows: a1->a10->a9, a1->a18->a9, a1->c6->v2->a9. The function involves potential malicious behaviors A, B, C, and the threat level is classified as Malicious."
                                    }},
                                    "Taint_Analysis": {{
                                        "fun_name": "sub_123456(v1)",
                                        "is_data_sources_same": false,
                                        "danger": "Benign",
                                        "description": "Upon analysis, these three operations do not have the same file data source or file handle"
                                    }}
                                6) If you are ready, please reply 'Understood'.
                                '''},
                            {"role": "assistant", "content": "Understood"},
                            {"role": "user",
                             "content": f"fun_name:{name}\nexternal function import:{import_names_single}\nfile_read_functions_and_parameters:{fun_1}\nfile_read_global_variables:{pub_1}\nfile_read_functions_and_parameters:{fun_2}\nfile_read_global_variables:{pub_2}\nfile_read_functions_and_parameters:{fun_3}\nfile_read_global_variables:{pub_3}\nfunction_body:\n{body}"},
                        ]
                    )
                message_content = response.choices[0].message.content

                match = re.search(r'```json\s*(\{.*?\})\s*```', message_content, re.DOTALL)
                if match:
                    json_content = match.group(1).strip()

                    parsed_json = json.loads(json_content)
                    res.append((leaf_123, parsed_json))
                    break
            except:
                pass
    return res

if __name__ == '__main__':
    subfolders = [f.path for f in os.scandir(root_path) if f.is_dir()]
    for subfolder in subfolders:
        name = os.path.basename(subfolder)
        try:
            with open(subfolder + '/res3' + ".json", "r") as f:
                content = json.load(f)
        except:
            print("skip:" + name)
            continue
        with open(subfolder + '/' + name + ".c", 'r', encoding='utf-8', errors='ignore') as file:
            program = file.read()
        nodes = content.get("sub_123", {}).get("nodes", {})
        if len(nodes) == 0:
            print("skip:"+name)
            continue
        if os.path.exists(root_path + name + '/' + name + ".pkl"):
            print("already_completed:" + name)
            continue
        blocks = re.split(r'//----- (.*?) -{20,}', program)
        all_functions = []

        for i in range(1, len(blocks), 2):
            comment = blocks[i].strip()
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
                all_functions.append((function_name, function_body))
            elif function_name_match2:
                function_name = function_name_match2.group(1)
                all_functions.append((function_name, function_body))
            else:
                continue

        function_dict = {name: body for name, body in all_functions}
        blocks = blocks[0]
        blocks = re.split(r'// Data declarations', blocks)
        blocks = blocks[1]
        blocks = re.split('\n', blocks)
        variable_names = []
        import_names = []


        for line in blocks:
            pattern1 = re.compile(r'\(\w+\s+\*([a-zA-Z_]\w*)\)')
            pattern2 = re.compile(r'\b(?:[a-zA-Z_][a-zA-Z0-9_]*\s+)?([a-zA-Z_][a-zA-Z0-9_]*)(?:\s*\[.*?\])?\s*(?:=|;)')
            match = pattern1.findall(line)
            match2 = pattern2.findall(line)
            if len(match) > 0:
                if "extern" in line:
                    import_names.append(match[0])
                else:
                    variable_names.append(match[0])
            elif len(match2) > 0:
                if "extern" in line:
                    import_names.append(match2[0])
                else:
                    variable_names.append(match2[0])
            else:
                pass

        orders = []
        org_leafs = []
        for i in range(1, 4):
            paths_key = f'paths_123_{i}'
            paths = content[paths_key]
            edges = []
            leafs = []

            for path in paths:
                for edge in path['path']['edges']:
                    if edge not in edges:
                        edges.append(edge)
                if path["start"] == path["end"]:
                    edge = ['flag_start', path["start"]]
                    if edge not in edges:
                        edges.append(edge)
                leafs.append(path["end"])

            order = find_leaf_order(edges)
            orders.append(order)
            org_leafs.append(leafs)

        for leaf in content['sub_123']['leafs']:
            orders = [[item for item in order if item != leaf] for order in orders]
        orders = [[item for item in order if item != 'flag_start'] for order in orders]

        order1 = orders[0][-30:] if len(orders[0]) > 30 else orders[0]
        order2 = orders[1][-30:] if len(orders[1]) > 30 else orders[1]
        order3 = orders[2][-30:] if len(orders[2]) > 30 else orders[2]

        org_leafs1, org_leafs2, org_leafs3 = org_leafs

        try:
            dataflow1, dataflow_pub1 = analyze_function(1, order1)
            dataflow2, dataflow_pub2 = analyze_function(2, order2)
            dataflow3, dataflow_pub3 = analyze_function(3, order3)
        except Exception as e:
            print(f"Failed to analyze function: {e}")
        try:
            res = analyze_function_join(dataflow1, dataflow_pub1, dataflow2,dataflow_pub2,dataflow3,dataflow_pub3)
        except Exception as e:
            print(f"Failed to analyze function: {e}")
        try:
            import pickle
            with open(root_path + name + '/' + name + ".pkl", 'wb') as file:
                pickle.dump((dataflow1, dataflow_pub1, dataflow2,dataflow_pub2,dataflow3,dataflow_pub3,res), file)
            print("success:" + name)
        except Exception as e:
            print(f"Failed to analyze function: {e}")



