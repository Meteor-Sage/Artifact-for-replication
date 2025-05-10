from openai import OpenAI
import json
import os
import re
import hyper_parameters
import concurrent.futures
from collections import defaultdict, deque
import subgraph
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

        if type == 1:
            des = "encryption"
        elif type == 3:
            des = "find"
        else:
            des = "suspicious"

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
                                 Your task is to analyze a decompiled function using the concept of reverse taint analysis to identify the source of data, and determine if it potentially originates from malicious ransomware.
                                 Rules and conditions:
                                 1)Identify the location of {des} data behavior in the code.
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
    return dataflow, dataflow_pub

if __name__ == '__main__':
    subfolders = [f.path for f in os.scandir(root_path) if f.is_dir()]
    for subfolder in subfolders:
        name = os.path.basename(subfolder)
        if not os.path.exists(root_path + name + '/' + "crypt_function") and not os.path.exists(root_path + name + '/' + "danger_word_function"):
            print("benign:"+name)
            continue
        try:
            with open(subfolder + '/res3' + ".json", "r") as f:
                content = json.load(f)
            nodes = content.get("sub_123", {}).get("nodes", {})
            if len(nodes) != 0:
                print("already_completed:" + name)
                continue
        except:
            pass
        with open(subfolder + '/' + name + ".c", 'r', encoding='utf-8', errors='ignore') as file:
            program = file.read()

        csv_file = subfolder + '/' + name + '.csv'

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

        order1 = []
        order2 = []
        order3 = []
        try:
            with open(subfolder + '/' + 'crypt_function', 'r') as rf:
                crypt_content = rf.read()
            nodes1, edges1 = subgraph.parse_graph(crypt_content)
            order1 = find_leaf_order(edges1)
        except:
            pass
        try:
            with open(subfolder + '/' + 'danger_word_function', 'r') as rf:
                crypt_content = rf.read()
            nodes2, edges2 = subgraph.parse_graph(crypt_content)
            order2 = find_leaf_order(edges2)
        except:
            pass
        try:
            with open(subfolder + '/' + 'find_file_function', 'r') as rf:
                crypt_content = rf.read()
            nodes3, edges3 = subgraph.parse_graph(crypt_content)
            order3 = find_leaf_order(edges3)
        except:
            pass

        order1 = order1[-30:] if len(order1) > 30 else order1
        order2 = order2[-30:] if len(order2) > 30 else order2
        order3 = order3[-30:] if len(order3) > 30 else order3


        try:
            dataflow1, dataflow_pub1 = analyze_function(1, order1)
            dataflow2, dataflow_pub2 = analyze_function(2, order2)
            dataflow3, dataflow_pub3 = analyze_function(3, order3)
        except Exception as e:
            print(f"Failed to analyze function: {e}")

        try:
            import pickle
            with open(root_path + name + '/' + name + "_other.pkl", 'wb') as file:
                pickle.dump((dataflow1, dataflow_pub1, dataflow2,dataflow_pub2,dataflow3,dataflow_pub3), file)
            print("success:" + name)
        except Exception as e:
            print(f"Failed to analyze function: {e}")

